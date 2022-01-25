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
	"net"
	"testing"
)

func TestListenAnyUDP4(t *testing.T) {
	server, err := ListenAnyUDP4(0)
	if err != nil {
		t.Fatal(err)
	}
	serverPort := server.LocalAddr().(*net.UDPAddr).Port
	serverAddr1 := &net.UDPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: serverPort,
	}
	client1, err := net.DialUDP("udp", nil, serverAddr1)
	if err != nil {
		t.Fatal(err)
	}
	serverAddr2 := &net.UDPAddr{
		IP:   net.ParseIP("127.0.0.2"),
		Port: serverPort,
	}
	client2, err := net.DialUDP("udp", nil, serverAddr2)
	if err != nil {
		t.Fatal(err)
	}

	// Receive a packet on 127.0.0.1
	if _, err := client1.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2)
	n, src, dst, err := server.ReadToFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("Unexpected length: %d", n)
	}
	if buf[0] != 1 {
		t.Errorf("Unexpected contents: %v", buf[:n])
	}
	if src == nil {
		t.Error("No source address")
	}
	if dst.String() != "127.0.0.1" {
		t.Errorf("Unexpected destination: %v", dst)
	}

	// Receive a packet on 127.0.0.2
	if _, err := client2.Write([]byte{2}); err != nil {
		t.Fatal(err)
	}
	n, src, dst, err = server.ReadToFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("Unexpected length: %d", n)
	}
	if buf[0] != 2 {
		t.Errorf("Unexpected contents: %v", buf[:n])
	}
	if src == nil {
		t.Error("No source address")
	}
	if dst.String() != "127.0.0.2" {
		t.Errorf("Unexpected destination: %v", dst)
	}
}

func TestSendAnyUDP4(t *testing.T) {
	server, err := ListenAnyUDP4(0)
	if err != nil {
		t.Fatal(err)
	}
	serverPort := server.LocalAddr().(*net.UDPAddr).Port
	client, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	clientAddr := client.LocalAddr().(*net.UDPAddr)

	serverIP1 := net.ParseIP("127.0.0.1")
	serverIP2 := net.ParseIP("127.0.0.2")

	// Send from 127.0.0.1
	if _, err := server.WriteToFrom([]byte{1}, clientAddr, serverIP1); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2)
	n, src, err := client.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("Unexpected length: %d", n)
	}
	if buf[0] != 1 {
		t.Errorf("Unexpected contents: %v", buf[:n])
	}
	udpSrc := src.(*net.UDPAddr)
	if !udpSrc.IP.Equal(serverIP1) {
		t.Errorf("Wrong source IP: %v", src)
	}
	if udpSrc.Port != serverPort {
		t.Errorf("Wrong source port: %v", src)
	}

	// Send from 127.0.0.2
	if _, err := server.WriteToFrom([]byte{2}, clientAddr, serverIP2); err != nil {
		t.Fatal(err)
	}
	n, src, err = client.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("Unexpected length: %d", n)
	}
	if buf[0] != 2 {
		t.Errorf("Unexpected contents: %v", buf[:n])
	}
	udpSrc = src.(*net.UDPAddr)
	if !udpSrc.IP.Equal(serverIP2) {
		t.Errorf("Wrong source IP: %v", src)
	}
	if udpSrc.Port != serverPort {
		t.Errorf("Wrong source port: %v", src)
	}
}

func TestListenAnyUDP6(t *testing.T) {
	server, err := ListenAnyUDP6(0)
	if err != nil {
		t.Fatal(err)
	}
	serverPort := server.LocalAddr().(*net.UDPAddr).Port
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, iface := range interfaces {
		addrs, err := iface.Addrs()
		if err != nil {
			t.Fatal(err)
		}
		for _, addr := range addrs {
			ip, _, err := net.ParseCIDR(addr.String())
			if err != nil {
				t.Fatal(err)
			}
			if ip.To4() != nil {
				continue // Ignore IPv4
			}

			// Receive a packet on this IP address.
			serverAddr := &net.UDPAddr{IP: ip, Port: serverPort, Zone: iface.Name}
			client, err := net.DialUDP("udp6", nil, serverAddr)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := client.Write([]byte{1}); err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, 2)
			n, src, dst, err := server.ReadToFrom(buf)
			if err != nil {
				t.Fatal(err)
			}
			if n != 1 {
				t.Errorf("Unexpected length: %d", n)
			}
			if buf[0] != 1 {
				t.Errorf("Unexpected contents: %v", buf[:n])
			}
			if src == nil {
				t.Error("No source address")
			}
			if !ip.Equal(dst) {
				t.Errorf("Unexpected destination: %v", dst)
			}
		}
	}
}

func TestSendAnyUDP6(t *testing.T) {
	server, err := ListenAnyUDP6(0)
	if err != nil {
		t.Fatal(err)
	}
	serverPort := server.LocalAddr().(*net.UDPAddr).Port
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, iface := range interfaces {
		addrs, err := iface.Addrs()
		if err != nil {
			t.Fatal(err)
		}
		for _, addr := range addrs {
			ip, _, err := net.ParseCIDR(addr.String())
			if err != nil {
				t.Fatal(err)
			}
			if ip.To4() != nil {
				continue // Ignore IPv4
			}

			// Start a client listening on this IP.
			clientInitAddr := &net.UDPAddr{IP: ip, Zone: iface.Name}
			client, err := net.ListenUDP("udp6", clientInitAddr)
			if err != nil {
				t.Fatal(err)
			}
			clientAddr := client.LocalAddr().(*net.UDPAddr)

			// Send a packet to the client from the same IP.  This should
			// avoid any issues with cross-interface routing rules.
			if _, err := server.WriteToFrom([]byte{1}, clientAddr, ip); err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, 2)
			n, src, err := client.ReadFromUDP(buf)
			if err != nil {
				t.Fatal(err)
			}
			if n != 1 {
				t.Errorf("Unexpected length: %d", n)
			}
			if buf[0] != 1 {
				t.Errorf("Unexpected contents: %v", buf[:n])
			}
			if !src.IP.Equal(ip) {
				t.Errorf("Unexpected source IP (%v)", src.IP)
			}
			if src.Port != serverPort {
				t.Errorf("Unexpected source port: %d", src.Port)
			}
		}
	}
}
