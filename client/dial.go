// Copyright 2021 The Outline Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package client

import (
	"errors"
	"io"
	"net"
	"os"
	"strconv"

	onet "github.com/Jigsaw-Code/outline-ss-server/net"
	"github.com/Jigsaw-Code/outline-ss-server/net/ipset"
)

// This dialer handles refreshing, confirming, and disconfirming proxy IPs.
// It implements a heuristic state machine: an IP is confirmed when a signal
// indicates that it is working correctly, and disconfimed when a signal
// suggests that it is not.  When an IP is confirmed, all subsequent TCP
// sockets and UDP packets will flow only to that IP.  Otherwise, TCP sockets
// will use standard hostname-based connection, and UDP packets will try
// known IPs at random.
type dialer struct {
	host string
	port int
	IPs  ipset.IPSet
}

func makeDialer(host string, port int) (*dialer, error) {
	d := &dialer{host: host, port: port}
	if err := d.IPs.Add(host); err != nil {
		return nil, err
	}
	return d, nil
}

// DialTCP connects to the dialer's host and port, using a confirmed IP from
// `ips` if possible.  It will disconfirm failing IPs.  The returned ConnMonitor
// can be applied to the decrypted channel to confirm the IP if it appears to be
// working well, or disconfirm if a post-handshake error occurs.
func (d *dialer) DialTCP() (*net.TCPConn, onet.ConnMonitor, error) {
	if confirmedIP := d.IPs.Confirmed(); confirmedIP != nil {
		// Use a known-working IP address for the proxy.
		proxyAddr := &net.TCPAddr{IP: confirmedIP, Port: d.port}
		proxyConn, err := net.DialTCP("tcp", nil, proxyAddr)
		if err == nil {
			return proxyConn, &connMonitor{ip: confirmedIP, ips: &d.IPs}, nil
		}
		d.IPs.Disconfirm(confirmedIP)
	}
	// Use Go's built-in fallback and Happy Eyeballs logic to identify a working
	// address.  This will cause redundant DNS queries on a fresh client until an
	// IP is confirmed, but most OSes have a built-in DNS cache so that should not
	// be too expensive.
	proxyAddr := net.JoinHostPort(d.host, strconv.Itoa(d.port))
	proxyConn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		return nil, nil, err
	}
	proxyIP := proxyConn.RemoteAddr().(*net.TCPAddr).IP
	monitor := &connMonitor{ip: proxyIP, ips: &d.IPs}
	return proxyConn.(*net.TCPConn), monitor, nil
}

// UDPWrite uses `conn` to send `buf` to `port` on a routable IP from `ips`.
// Non-routable addresses will be disconfirmed.  The caller can confirm the
// IP if valid replies are received.
func (d *dialer) UDPWrite(conn *net.UDPConn, buf []byte) error {
	addr := net.UDPAddr{IP: d.IPs.Confirmed(), Port: d.port}
	if addr.IP != nil {
		if _, err := conn.WriteToUDP(buf, &addr); err == nil {
			return nil
		}
		// A confirmed address could become non-routable if the IPv6
		// network interface is disconnected.
		d.IPs.Disconfirm(addr.IP)
	}

	// This loop's main purpose is to skip IPv6 addresses on v4-only clients.
	err := errors.New("IPSet is empty")
	for _, addr.IP = range d.IPs.GetAll() {
		_, err = conn.WriteToUDP(buf, &addr)
		if err == nil {
			return nil
		}
	}
	return err
}

type connMonitor struct {
	confirmed bool
	ip        net.IP // Remote IP of the monitored connection
	ips       *ipset.IPSet
}

func (m *connMonitor) OnRead(n int64, err error) {
	if err != nil {
		if errors.Is(err, io.EOF) {
			if m.confirmed {
				// Reconfirm on clean shutdown after successful download.
				m.ips.AddAndConfirm(m.ip)
			}
		} else if !errors.Is(err, os.ErrDeadlineExceeded) {
			// Unclean shutdown (timeout or reset).
			m.ips.Disconfirm(m.ip)
		}
	} else if n > 0 && !m.confirmed {
		// Confirm on the first successful read.
		m.ips.AddAndConfirm(m.ip)
		m.confirmed = true
	}
}

func (m *connMonitor) OnWrite(n int64, err error) {
	if err != nil && !errors.Is(err, io.EOF) &&
		!errors.Is(err, os.ErrDeadlineExceeded) {
		m.ips.Disconfirm(m.ip)
	}
}
