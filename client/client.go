package client

import (
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"

	onet "github.com/Jigsaw-Code/outline-ss-server/net"
	"github.com/Jigsaw-Code/outline-ss-server/net/ipset"
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
	cipher, err := ss.NewCipher(cipherName, password)
	if err != nil {
		return nil, err
	}
	d := ssClient{proxyHost: host, proxyPort: port, cipher: cipher}
	// If `host` is a domain name, the client resolves it here to provide clearer
	// error reporting and simplify UDP forwarding.  If these IPs all stop working,
	// any TCP connection will re-resolve the name and add a working IP to the set.
	if err := d.ips.Add(host); err != nil {
		return nil, fmt.Errorf("Failed to resolve proxy address: %v", err)
	}
	return &d, nil
}

type ssClient struct {
	proxyHost string
	proxyPort int
	cipher    *ss.Cipher
	ips       ipset.IPSet
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
	proxyConn, err := c.dialProxy(laddr)
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
	return onet.WrapConn(proxyConn, ssr, ssw), nil
}

func (c *ssClient) dialProxy(laddr *net.TCPAddr) (*net.TCPConn, error) {
	if confirmedIP := c.ips.Confirmed(); confirmedIP != nil {
		// Use a known-working IP address for the proxy.
		proxyAddr := &net.TCPAddr{IP: confirmedIP, Port: c.proxyPort}
		proxyConn, err := net.DialTCP("tcp", laddr, proxyAddr)
		if err != nil {
			c.ips.Disconfirm(confirmedIP)
		}
		return proxyConn, err
	}
	// Use Go's built-in fallback and Happy Eyeballs logic to identify a working
	// address.  This will cause redundant DNS queries on a fresh client until an
	// IP is confirmed, but most OSes have a built-in DNS cache so that should not
	// be too expensive.
	// Note: laddr is ignored.  TODO: Remove laddr from the arguments.
	proxyAddr := net.JoinHostPort(c.proxyHost, strconv.Itoa(c.proxyPort))
	proxyConn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		return nil, err
	}
	c.ips.AddAndConfirm(proxyConn.RemoteAddr().(*net.TCPAddr).IP)
	return proxyConn.(*net.TCPConn), nil
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
	if err := c.send(buf); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *packetConn) send(buf []byte) error {
	var ips []net.IP
	if confirmedIP := c.client.ips.Confirmed(); confirmedIP != nil {
		ips = []net.IP{confirmedIP}
	} else {
		// GetAll returns the IPs in shuffled order, so each packet will try
		// a different IP at random until an IP is confirmed working.
		ips = c.client.ips.GetAll()
		if len(ips) == 0 {
			// If LookupIPAddr never returns ({}, nil), this is unreachable.
			return errors.New("No IPs for the proxy")
		}
	}

	// This loop's main purpose is to skip IPv6 addresses on v4-only clients.
	var err error
	proxyAddr := net.UDPAddr{Port: c.client.proxyPort}
	for _, proxyAddr.IP = range ips {
		_, err = c.UDPConn.WriteToUDP(buf, &proxyAddr)
		if err == nil {
			return nil
		}
		// A confirmed address could become non-routable if the IPv6
		// network interface is disconnected.
		c.client.ips.Disconfirm(proxyAddr.IP)
	}
	return err
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
	c.client.ips.Confirm(proxyAddr.IP)
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
