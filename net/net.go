package net

import (
	"errors"
	"fmt"
	"io"
	"net"
	"runtime"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// DuplexConn is a net.Conn that allows for closing only the reader or writer end of
// it, supporting half-open state.
type DuplexConn interface {
	net.Conn
	// Closes the Read end of the connection, allowing for the release of resources.
	// No more reads should happen.
	CloseRead() error
	// Closes the Write end of the connection. An EOF or FIN signal may be
	// sent to the connection target.
	CloseWrite() error
}

type duplexConnAdaptor struct {
	DuplexConn
	r io.Reader
	w io.Writer
}

func (dc *duplexConnAdaptor) Read(b []byte) (int, error) {
	return dc.r.Read(b)
}
func (dc *duplexConnAdaptor) WriteTo(w io.Writer) (int64, error) {
	return io.Copy(w, dc.r)
}
func (dc *duplexConnAdaptor) CloseRead() error {
	return dc.DuplexConn.CloseRead()
}
func (dc *duplexConnAdaptor) Write(b []byte) (int, error) {
	return dc.w.Write(b)
}
func (dc *duplexConnAdaptor) ReadFrom(r io.Reader) (int64, error) {
	return io.Copy(dc.w, r)
}
func (dc *duplexConnAdaptor) CloseWrite() error {
	return dc.DuplexConn.CloseWrite()
}

// WrapDuplexConn wraps an existing DuplexConn with new Reader and Writer, but
// preserving the original CloseRead() and CloseWrite().
func WrapConn(c DuplexConn, r io.Reader, w io.Writer) DuplexConn {
	conn := c
	// We special-case duplexConnAdaptor to avoid multiple levels of nesting.
	if a, ok := c.(*duplexConnAdaptor); ok {
		conn = a.DuplexConn
	}
	return &duplexConnAdaptor{DuplexConn: conn, r: r, w: w}
}

func copyOneWay(leftConn, rightConn DuplexConn) (int64, error) {
	n, err := io.Copy(leftConn, rightConn)
	// Send FIN to indicate EOF
	leftConn.CloseWrite()
	// Release reader resources
	rightConn.CloseRead()
	return n, err
}

// Relay copies between left and right bidirectionally. Returns number of
// bytes copied from right to left, from left to right, and any error occurred.
// Relay allows for half-closed connections: if one side is done writing, it can
// still read all remaining data from its peer.
func Relay(leftConn, rightConn DuplexConn) (int64, int64, error) {
	type res struct {
		N   int64
		Err error
	}
	ch := make(chan res)

	go func() {
		n, err := copyOneWay(rightConn, leftConn)
		ch <- res{n, err}
	}()

	n, err := copyOneWay(leftConn, rightConn)
	rs := <-ch

	if err == nil {
		err = rs.Err
	}
	return n, rs.N, err
}

type ConnectionError struct {
	// TODO: create status enums and move to metrics.go
	Status  string
	Message string
	Cause   error
}

func NewConnectionError(status, message string, cause error) *ConnectionError {
	return &ConnectionError{Status: status, Message: message, Cause: cause}
}

// ReadFromWithDst reads one packet from `conn` into `b` and returns the number
// of bytes read, the source address, and the destination IP address.  It enables
// recovery of the destination IP, which is otherwise lost for UDP connections
// that are bound to `0.0.0.0` or `::`.
func ReadFromWithDst(conn net.PacketConn, b []byte) (n int, src *net.UDPAddr, dst net.IP, err error) {
	var tmpSrc net.Addr
	if conn.LocalAddr().Network() == "udp4" {
		ipv4Conn := ipv4.NewPacketConn(conn)
		if err = ipv4Conn.SetControlMessage(ipv4.FlagDst, true); err != nil {
			return
		}
		var cm *ipv4.ControlMessage
		if n, cm, tmpSrc, err = ipv4Conn.ReadFrom(b); err != nil {
			return
		}
		if cm != nil {
			dst = cm.Dst
		} else if runtime.GOOS != "windows" {
			err = errors.New("control data is missing")
			return
		}
	} else if conn.LocalAddr().Network() == "udp6" {
		ipv6Conn := ipv6.NewPacketConn(conn)
		if err = ipv6Conn.SetControlMessage(ipv6.FlagDst, true); err != nil {
			return
		}
		var cm *ipv6.ControlMessage
		if n, cm, tmpSrc, err = ipv6Conn.ReadFrom(b); err != nil {
			return
		}
		if cm != nil {
			dst = cm.Dst
		} else if runtime.GOOS != "windows" {
			err = errors.New("control data is missing")
			return
		}
	} else {
		err = fmt.Errorf("unsupported network: %s", conn.LocalAddr().Network())
		return
	}
	src = tmpSrc.(*net.UDPAddr)
	return
}

// WriteToWithSrc sends `b` to `dst` on `conn` from the specified source IP.
// This can be useful when the system has multiple IP addresses of the same family.
// Similar functionality can be achieved by binding a new UDP socket to a specific local address,
// but that might run into problems if the port is already bound by an existing socket.
func WriteToWithSrc(conn net.PacketConn, b []byte, src net.IP, dst *net.UDPAddr) (int, error) {
	if conn.LocalAddr().Network() == "udp4" {
		cm := &ipv4.ControlMessage{Src: src}
		return ipv4.NewPacketConn(conn).WriteTo(b, cm, dst)
	} else if conn.LocalAddr().Network() == "udp6" {
		cm := &ipv6.ControlMessage{Src: src}
		return ipv6.NewPacketConn(conn).WriteTo(b, cm, dst)
	} else {
		return 0, fmt.Errorf("unsupported network: %s", conn.LocalAddr().Network())
	}
}