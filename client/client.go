package client

import (
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	onet "github.com/Jigsaw-Code/outline-ss-server/net"
	ss "github.com/Jigsaw-Code/outline-ss-server/shadowsocks"
	"github.com/Jigsaw-Code/outline-ss-server/slicepool"
	"github.com/shadowsocks/go-shadowsocks2/socks"
)

// clientUDPBufferSize is the maximum supported UDP packet size in bytes.
const clientUDPBufferSize = 16 * 1024

// udpPool stores the byte slices used for storing encrypted packets.
var udpPool = slicepool.MakePool(clientUDPBufferSize)

// Client is a client for Shadowsocks TCP and UDP connections.
type Client interface {
	// DialTCP connects to `raddr` over TCP though a Shadowsocks proxy.
	// `laddr` is a local bind address, a local address is automatically chosen if nil.
	// `raddr` has the form `host:port`, where `host` can be a domain name or IP address.
	DialTCP(laddr *net.TCPAddr, raddr string) (onet.DuplexConn, error)

	// ListenUDP relays UDP packets though a Shadowsocks proxy.
	// `laddr` is a local bind address, a local address is automatically chosen if nil.
	ListenUDP(laddr *net.UDPAddr) (net.PacketConn, error)
}

// NewClient creates a client that routes connections to a Shadowsocks proxy listening at
// `host:port`, with authentication parameters `cipher` (AEAD) and `password`.
// TODO: add a dialer argument to support proxy chaining and transport changes.
func NewClient(host string, port int, password, cipherName string) (Client, error) {
	// If `host` is a domain name, the client resolves it here to provide clearer
	// error reporting and simplify UDP forwarding.  If these IPs all stop working,
	// any TCP connection will re-resolve the name and add a working IP to the set.
	dialer, err := makeDialer(host, port)
	if err != nil {
		return nil, fmt.Errorf("Failed to resolve proxy address: %v", err)
	}
	cipher, err := ss.NewCipher(cipherName, password)
	if err != nil {
		return nil, err
	}
	return &ssClient{dialer, cipher}, nil
}

type ssClient struct {
	dialer *dialer
	cipher *ss.Cipher
}

// This code contains an optimization to send the initial client payload along with
// the Shadowsocks handshake.  This saves one packet during connection, and also
// reduces the distinctiveness of the connection pattern.
//
// Normally, the initial payload will be sent as soon as the socket is connected,
// except for delays due to inter-process communication.  However, some protocols
// expect the server to send data first, in which case there is no client payload.
// We therefore use a short delay, longer than any reasonable IPC but shorter than
// typical network latency.  (In an Android emulator, the 90th percentile delay
// was ~1 ms.)  If no client payload is received by this time, we connect without it.
const helloWait = 10 * time.Millisecond

func (c *ssClient) DialTCP(laddr *net.TCPAddr, raddr string) (onet.DuplexConn, error) {
	socksTargetAddr := socks.ParseAddr(raddr)
	if socksTargetAddr == nil {
		return nil, errors.New("Failed to parse target address")
	}
	proxyConn, monitor, err := c.dialer.DialTCP()
	if err != nil {
		return nil, err
	}
	ssw := ss.NewShadowsocksWriter(proxyConn, c.cipher)
	_, err = ssw.LazyWrite(socksTargetAddr)
	if err != nil {
		proxyConn.Close()
		return nil, errors.New("Failed to write target address")
	}
	time.AfterFunc(helloWait, func() {
		ssw.Flush()
	})
	ssr := ss.NewShadowsocksReader(proxyConn, c.cipher)
	ssConn := onet.WrapConn(proxyConn, ssr, ssw)
	return onet.MonitorConn(ssConn, monitor), nil
}

func (c *ssClient) ListenUDP(laddr *net.UDPAddr) (net.PacketConn, error) {
	pc, err := net.ListenUDP("udp", laddr)
	if err != nil {
		return nil, err
	}
	conn := packetConn{UDPConn: pc, client: c}
	return &conn, nil
}

type packetConn struct {
	*net.UDPConn
	client *ssClient
}

// WriteTo encrypts `b` and writes to `addr` through the proxy.
func (c *packetConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	socksTargetAddr := socks.ParseAddr(addr.String())
	if socksTargetAddr == nil {
		return 0, errors.New("Failed to parse target address")
	}
	lazySlice := udpPool.LazySlice()
	cipherBuf := lazySlice.Acquire()
	defer lazySlice.Release()
	saltSize := c.client.cipher.SaltSize()
	// Copy the SOCKS target address and payload, reserving space for the generated salt to avoid
	// partially overlapping the plaintext and cipher slices since `Pack` skips the salt when calling
	// `AEAD.Seal` (see https://golang.org/pkg/crypto/cipher/#AEAD).
	plaintextBuf := append(append(cipherBuf[saltSize:saltSize], socksTargetAddr...), b...)
	buf, err := ss.Pack(cipherBuf, plaintextBuf, c.client.cipher)
	if err != nil {
		return 0, err
	}
	err = c.client.dialer.UDPWrite(c.UDPConn, buf)
	return len(b), err
}

// ReadFrom reads from the embedded PacketConn and decrypts into `b`.
func (c *packetConn) ReadFrom(b []byte) (int, net.Addr, error) {
	lazySlice := udpPool.LazySlice()
	cipherBuf := lazySlice.Acquire()
	defer lazySlice.Release()
	n, proxyAddr, err := c.UDPConn.ReadFromUDP(cipherBuf)
	if err != nil {
		return 0, nil, err
	}
	// Decrypt in-place.
	buf, err := ss.Unpack(nil, cipherBuf[:n], c.client.cipher)
	if err != nil {
		return 0, nil, err
	}
	socksSrcAddr := socks.SplitAddr(buf)
	if socksSrcAddr == nil {
		return 0, nil, errors.New("Failed to read source address")
	}
	srcAddr := NewAddr(socksSrcAddr.String(), "udp")
	n = copy(b, buf[len(socksSrcAddr):]) // Strip the SOCKS source address
	if len(b) < len(buf)-len(socksSrcAddr) {
		return n, srcAddr, io.ErrShortBuffer
	}
	c.client.dialer.IPs.Confirm(proxyAddr.IP)
	return n, srcAddr, nil
}

type addr struct {
	address string
	network string
}

func (a *addr) String() string {
	return a.address
}

func (a *addr) Network() string {
	return a.network
}

// NewAddr returns a net.Addr that holds an address of the form `host:port` with a domain name or IP as host.
// Used for SOCKS addressing.
func NewAddr(address, network string) net.Addr {
	return &addr{address: address, network: network}
}
