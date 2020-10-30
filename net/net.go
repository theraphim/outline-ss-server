package net

import (
	"fmt"
	"io"
	"net"
	"syscall"
)

// TrySyscallConn returns the RawConn that underlies conn, if conn supports this.
func TrySyscallConn(conn net.Conn) (syscall.RawConn, error) {
	supportedConn, ok := conn.(interface {
		SyscallConn() (syscall.RawConn, error)
	})
	if !ok {
		return nil, fmt.Errorf("No raw conn access: %v", conn)
	}
	return supportedConn.SyscallConn()
}

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
func (dc *duplexConnAdaptor) SyscallConn() (syscall.RawConn, error) {
	return TrySyscallConn(dc.DuplexConn)
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

// GetMSS returns the TCP Maximum Segment Size if conn is a TCP connection
// and support RawConn access.
func GetMSS(conn net.Conn) (mss int, err error) {
	var rawConn syscall.RawConn
	rawConn, err = TrySyscallConn(conn)
	if err != nil {
		return
	}
	rawConn.Control(func(fd uintptr) {
		// This should work on POSIX platforms and Windows 10.
		mss, err = syscall.GetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_MAXSEG)
	})
	return
}
