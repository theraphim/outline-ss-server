// Copyright 2022 Jigsaw Operations LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package net

import (
	"errors"
	"net"
	"runtime"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// UDPAnyConn extends net.PacketConn to allow reporting the destination IP
// of incoming packets, and setting the source IP of outgoing packets.  This
// is relevant for UDP connections that are bound to `0.0.0.0` or `::`.  In
// these cases, net.PacketConn is not sufficient to enable sending a reply
// from the expected source IP.
type UDPAnyConn interface {
	net.PacketConn
	ReadToFrom(p []byte) (n int, src *net.UDPAddr, dst net.IP, err error)
	WriteToFrom(p []byte, dst *net.UDPAddr, src net.IP) (int, error)
}

type udpAnyConnV4 struct {
	net.PacketConn
	v4 ipv4.PacketConn
}

// ListenAnyUDP4 returns a UDPAnyConn that is listening on all IPv4 addresses
// at the specified port. If `port` is zero, the kernel will choose an open port.
func ListenAnyUDP4(port int) (UDPAnyConn, error) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{Port: port})
	if err != nil {
		return nil, err
	}
	anyConn := &udpAnyConnV4{conn, *ipv4.NewPacketConn(conn)}
	if err = anyConn.v4.SetControlMessage(ipv4.FlagDst, true); err != nil {
		return nil, err
	}
	return anyConn, nil
}

func (c *udpAnyConnV4) ReadToFrom(p []byte) (n int, src *net.UDPAddr, dst net.IP, err error) {
	var cm *ipv4.ControlMessage
	var tmpSrc net.Addr
	if n, cm, tmpSrc, err = c.v4.ReadFrom(p); err != nil {
		return
	}
	if cm != nil {
		dst = cm.Dst
	} else if runtime.GOOS != "windows" {
		err = errors.New("control data is missing")
		return
	}
	src = tmpSrc.(*net.UDPAddr)
	return
}

func (c *udpAnyConnV4) WriteToFrom(p []byte, dst *net.UDPAddr, src net.IP) (int, error) {
	cm := &ipv4.ControlMessage{Src: src}
	return c.v4.WriteTo(p, cm, dst)
}

type udpAnyConnV6 struct {
	net.PacketConn
	v6 ipv6.PacketConn
}

// ListenAnyUDP4 returns a UDPAnyConn that is listening on all IPv6 addresses
// at the specified port. If `port` is zero, the kernel will choose an open port.
func ListenAnyUDP6(port int) (UDPAnyConn, error) {
	conn, err := net.ListenUDP("udp6", &net.UDPAddr{Port: port})
	if err != nil {
		return nil, err
	}
	anyConn := &udpAnyConnV6{conn, *ipv6.NewPacketConn(conn)}
	if err = anyConn.v6.SetControlMessage(ipv6.FlagDst, true); err != nil {
		return nil, err
	}
	return anyConn, nil
}

func (c *udpAnyConnV6) ReadToFrom(p []byte) (n int, src *net.UDPAddr, dst net.IP, err error) {
	var cm *ipv6.ControlMessage
	var tmpSrc net.Addr
	if n, cm, tmpSrc, err = c.v6.ReadFrom(p); err != nil {
		return
	}
	if cm != nil {
		dst = cm.Dst
	} else if runtime.GOOS != "windows" {
		err = errors.New("control data is missing")
		return
	}
	src = tmpSrc.(*net.UDPAddr)
	return
}

func (c *udpAnyConnV6) WriteToFrom(p []byte, dst *net.UDPAddr, src net.IP) (int, error) {
	cm := &ipv6.ControlMessage{Src: src}
	return c.v6.WriteTo(p, cm, dst)
}
