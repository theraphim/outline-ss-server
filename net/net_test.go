// Copyright 2020 Jigsaw Operations LLC
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

func TestLocalhostMSS(t *testing.T) {
	l, err := net.ListenTCP("tcp", nil)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		serverConn, err := l.Accept()
		if err != nil {
			t.Error(err)
		}
		mss, err := GetMSS(serverConn.(*net.TCPConn))
		if err != nil {
			t.Error(err)
		}
		t.Logf("Server MSS: %d", mss)
		serverConn.Close()
		l.Close()
	}()

	conn, err := net.DialTCP("tcp", nil, l.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	mss, err := GetMSS(conn)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Client MSS: %d", mss)
	conn.Read(nil) // Block until the server closes the socket
}

func TestRemoteMSS(t *testing.T) {
	remote, err := net.ResolveTCPAddr("tcp", "www.google.com:443")
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.DialTCP("tcp", nil, remote)
	if err != nil {
		t.Fatal(err)
	}
	mss, err := GetMSS(conn)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Google MSS: %d", mss)
}
