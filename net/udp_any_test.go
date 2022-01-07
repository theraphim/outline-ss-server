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
