// Copyright 2018 Jigsaw Operations LLC
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

package service

import (
	"bytes"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	onet "github.com/Jigsaw-Code/outline-ss-server/net"
	"github.com/Jigsaw-Code/outline-ss-server/service/metrics"
	ss "github.com/Jigsaw-Code/outline-ss-server/shadowsocks"
	logging "github.com/op/go-logging"
	"github.com/shadowsocks/go-shadowsocks2/socks"
	"github.com/stretchr/testify/assert"
)

const timeout = 5 * time.Minute

var clientAddr = net.UDPAddr{IP: []byte{192, 0, 2, 1}, Port: 12345}
var targetAddr = net.UDPAddr{IP: []byte{192, 0, 2, 2}, Port: 54321}
var dnsAddr = net.UDPAddr{IP: []byte{192, 0, 2, 3}, Port: 53}
var proxyIP net.IP = []byte{192, 0, 2, 4}
var natCipher *ss.Cipher

func init() {
	logging.SetLevel(logging.INFO, "")
	natCipher, _ = ss.NewCipher(ss.TestCipher, "test password")
}

type packet struct {
	remote  *net.UDPAddr
	local   net.IP
	payload []byte
	err     error
}

type fakePacketConn struct {
	net.PacketConn
	send     chan packet
	recv     chan packet
	deadline time.Time
}

func makePacketConn() *fakePacketConn {
	return &fakePacketConn{
		send: make(chan packet, 1),
		recv: make(chan packet),
	}
}

func (conn *fakePacketConn) SetReadDeadline(deadline time.Time) error {
	conn.deadline = deadline
	return nil
}

func (conn *fakePacketConn) WriteTo(payload []byte, addr net.Addr) (int, error) {
	return conn.WriteToFrom(payload, addr.(*net.UDPAddr), nil)
}

func (conn *fakePacketConn) WriteToFrom(payload []byte, dst *net.UDPAddr, src net.IP) (int, error) {
	conn.send <- packet{dst, src, payload, nil}
	return len(payload), nil
}

func (conn *fakePacketConn) ReadFrom(buffer []byte) (int, net.Addr, error) {
	n, src, _, err := conn.ReadToFrom(buffer)
	return n, src, err
}

func (conn *fakePacketConn) ReadToFrom(buffer []byte) (int, *net.UDPAddr, net.IP, error) {
	pkt, ok := <-conn.recv
	if !ok {
		return 0, nil, nil, errors.New("Receive closed")
	}
	n := copy(buffer, pkt.payload)
	if n < len(pkt.payload) {
		return n, pkt.remote, pkt.local, io.ErrShortBuffer
	}
	return n, pkt.remote, pkt.local, pkt.err
}

func (conn *fakePacketConn) Close() error {
	close(conn.send)
	close(conn.recv)
	return nil
}

type udpReport struct {
	clientLocation, accessKey, status  string
	clientProxyBytes, proxyTargetBytes int
}

// Stub metrics implementation for testing NAT behaviors.
type natTestMetrics struct {
	metrics.ShadowsocksMetrics
	natEntriesAdded int
	upstreamPackets []udpReport
}

func (m *natTestMetrics) AddTCPProbe(clientLocation, status, drainResult string, port int, data metrics.ProxyMetrics) {
}
func (m *natTestMetrics) AddClosedTCPConnection(clientLocation, accessKey, status string, data metrics.ProxyMetrics, timeToCipher, duration time.Duration) {
}
func (m *natTestMetrics) GetLocation(net.Addr) (string, error) {
	return "", nil
}
func (m *natTestMetrics) SetNumAccessKeys(numKeys int, numPorts int) {
}
func (m *natTestMetrics) AddOpenTCPConnection(clientLocation string) {
}
func (m *natTestMetrics) AddUDPPacketFromClient(clientLocation, accessKey, status string, clientProxyBytes, proxyTargetBytes int, timeToCipher time.Duration) {
	m.upstreamPackets = append(m.upstreamPackets, udpReport{clientLocation, accessKey, status, clientProxyBytes, proxyTargetBytes})
}
func (m *natTestMetrics) AddUDPPacketFromTarget(clientLocation, accessKey, status string, targetProxyBytes, proxyClientBytes int) {
}
func (m *natTestMetrics) AddUDPNatEntry() {
	m.natEntriesAdded++
}
func (m *natTestMetrics) RemoveUDPNatEntry() {}

// Takes a validation policy, and returns the metrics it
// generates when localhost access is attempted
func sendToDiscard(payloads [][]byte, validator onet.TargetIPValidator) *natTestMetrics {
	ciphers, _ := MakeTestCiphers([]string{"asdf"})
	cipher := ciphers.SnapshotForClientIP(nil)[0].Value.(*CipherEntry).Cipher
	clientConn := makePacketConn()
	metrics := &natTestMetrics{}
	service := NewUDPService(timeout, ciphers, metrics)
	service.SetTargetIPValidator(validator)
	go service.Serve(clientConn)

	// Send one packet to the "discard" port on localhost
	targetAddr := socks.ParseAddr("127.0.0.1:9")
	for _, payload := range payloads {
		plaintext := append(targetAddr, payload...)
		ciphertext := make([]byte, cipher.SaltSize()+len(plaintext)+cipher.TagSize())
		ss.Pack(ciphertext, plaintext, cipher)
		clientConn.recv <- packet{
			remote: &net.UDPAddr{
				IP:   net.ParseIP("192.0.2.1"),
				Port: 54321,
			},
			local:   proxyIP,
			payload: ciphertext,
		}
	}

	service.GracefulStop()
	return metrics
}

func TestIPFilter(t *testing.T) {
	// Test both the first-packet and subsequent-packet cases.
	payloads := [][]byte{[]byte("payload1"), []byte("payload2")}

	t.Run("Localhost allowed", func(t *testing.T) {
		metrics := sendToDiscard(payloads, allowAll)
		assert.Equal(t, metrics.natEntriesAdded, 1, "Expected 1 NAT entry, not %d", metrics.natEntriesAdded)
	})

	t.Run("Localhost not allowed", func(t *testing.T) {
		metrics := sendToDiscard(payloads, onet.RequirePublicIP)
		assert.Equal(t, 0, metrics.natEntriesAdded, "Unexpected NAT entry on rejected packet")
		assert.Equal(t, 2, len(metrics.upstreamPackets), "Expected 2 reports, not %v", metrics.upstreamPackets)
		for _, report := range metrics.upstreamPackets {
			assert.Greater(t, report.clientProxyBytes, 0, "Expected nonzero input packet size")
			assert.Equal(t, 0, report.proxyTargetBytes, "No bytes should be sent due to a disallowed packet")
			assert.Equal(t, report.accessKey, "id-0", "Unexpected access key: %s", report.accessKey)
		}
	})
}

func TestUpstreamMetrics(t *testing.T) {
	// Test both the first-packet and subsequent-packet cases.
	const N = 10
	payloads := make([][]byte, 0)
	for i := 1; i <= N; i++ {
		payloads = append(payloads, make([]byte, i))
	}

	metrics := sendToDiscard(payloads, allowAll)

	assert.Equal(t, N, len(metrics.upstreamPackets), "Expected %d reports, not %v", N, metrics.upstreamPackets)
	for i, report := range metrics.upstreamPackets {
		assert.Equal(t, i+1, report.proxyTargetBytes, "Expected %d payload bytes, not %d", i+1, report.proxyTargetBytes)
		assert.Greater(t, report.clientProxyBytes, report.proxyTargetBytes, "Expected nonzero input overhead (%d > %d)", report.clientProxyBytes, report.proxyTargetBytes)
		assert.Equal(t, "id-0", report.accessKey, "Unexpected access key name: %s", report.accessKey)
		assert.Equal(t, "OK", report.status, "Wrong status: %s", report.status)
	}
}

func assertAlmostEqual(t *testing.T, a, b time.Time) {
	delta := a.Sub(b)
	limit := 100 * time.Millisecond
	if delta > limit || -delta > limit {
		t.Errorf("Times are not close: %v, %v", a, b)
	}
}

func TestNATEmpty(t *testing.T) {
	nat := newNATmap(timeout, &natTestMetrics{}, &sync.WaitGroup{})
	if nat.Get(&clientAddr, proxyIP) != nil {
		t.Error("Expected nil value from empty NAT map")
	}
}

func setupNAT() (*fakePacketConn, *fakePacketConn, *natconn) {
	nat := newNATmap(timeout, &natTestMetrics{}, &sync.WaitGroup{})
	clientConn := makePacketConn()
	targetConn := makePacketConn()
	nat.Add(&clientAddr, proxyIP, clientConn, natCipher, targetConn, "ZZ", "key id")
	entry := nat.Get(&clientAddr, proxyIP)
	return clientConn, targetConn, entry
}

func TestNATGet(t *testing.T) {
	_, targetConn, entry := setupNAT()
	if entry == nil {
		t.Fatal("Failed to find target conn")
	}
	if entry.PacketConn != targetConn {
		t.Error("Mismatched connection returned")
	}
}

func TestNATWrite(t *testing.T) {
	_, targetConn, entry := setupNAT()

	// Simulate one generic packet being sent
	buf := []byte{1}
	entry.WriteTo([]byte{1}, &targetAddr)
	assertAlmostEqual(t, targetConn.deadline, time.Now().Add(timeout))
	sent := <-targetConn.send
	if !bytes.Equal(sent.payload, buf) {
		t.Errorf("Mismatched payload: %v != %v", sent.payload, buf)
	}
	if sent.remote != &targetAddr {
		t.Errorf("Mismatched address: %v != %v", sent.remote, &targetAddr)
	}
}

func TestNATWriteDNS(t *testing.T) {
	_, targetConn, entry := setupNAT()

	// Simulate one DNS query being sent.
	buf := []byte{1}
	entry.WriteTo(buf, &dnsAddr)
	// DNS-only connections have a fixed timeout of 17 seconds.
	assertAlmostEqual(t, targetConn.deadline, time.Now().Add(17*time.Second))
	sent := <-targetConn.send
	if !bytes.Equal(sent.payload, buf) {
		t.Errorf("Mismatched payload: %v != %v", sent.payload, buf)
	}
	if sent.remote != &dnsAddr {
		t.Errorf("Mismatched address: %v != %v", sent.remote, &targetAddr)
	}
}

func TestNATWriteDNSMultiple(t *testing.T) {
	_, targetConn, entry := setupNAT()

	// Simulate three DNS queries being sent.
	buf := []byte{1}
	entry.WriteTo(buf, &dnsAddr)
	<-targetConn.send
	entry.WriteTo(buf, &dnsAddr)
	<-targetConn.send
	entry.WriteTo(buf, &dnsAddr)
	<-targetConn.send
	// DNS-only connections have a fixed timeout of 17 seconds.
	assertAlmostEqual(t, targetConn.deadline, time.Now().Add(17*time.Second))
}

func TestNATWriteMixed(t *testing.T) {
	_, targetConn, entry := setupNAT()

	// Simulate both non-DNS and DNS packets being sent.
	buf := []byte{1}
	entry.WriteTo(buf, &targetAddr)
	<-targetConn.send
	entry.WriteTo(buf, &dnsAddr)
	<-targetConn.send
	// Mixed DNS and non-DNS connections should have the user-specified timeout.
	assertAlmostEqual(t, targetConn.deadline, time.Now().Add(timeout))
}

func TestNATFastClose(t *testing.T) {
	clientConn, targetConn, entry := setupNAT()

	// Send one DNS query.
	query := []byte{1}
	entry.WriteTo(query, &dnsAddr)
	sent := <-targetConn.send
	// Send the response.
	response := []byte{1, 2, 3, 4, 5}
	received := packet{remote: &dnsAddr, payload: response}
	targetConn.recv <- received
	sent, ok := <-clientConn.send
	if !ok {
		t.Error("clientConn was closed")
	}
	if len(sent.payload) <= len(response) {
		t.Error("Packet is too short to be shadowsocks-AEAD")
	}
	if sent.remote != &clientAddr {
		t.Errorf("Address mismatch: %v != %v", sent.remote, clientAddr)
	}
	if !proxyIP.Equal(sent.local) {
		t.Errorf("Proxy IP mismatch: %v != %v", sent.local, proxyIP)
	}

	// targetConn should be scheduled to close immediately.
	assertAlmostEqual(t, targetConn.deadline, time.Now())
}

func TestNATNoFastClose_NotDNS(t *testing.T) {
	clientConn, targetConn, entry := setupNAT()

	// Send one non-DNS packet.
	query := []byte{1}
	entry.WriteTo(query, &targetAddr)
	sent := <-targetConn.send
	// Send the response.
	response := []byte{1, 2, 3, 4, 5}
	received := packet{remote: &targetAddr, payload: response}
	targetConn.recv <- received
	sent, ok := <-clientConn.send
	if !ok {
		t.Error("clientConn was closed")
	}
	if len(sent.payload) <= len(response) {
		t.Error("Packet is too short to be shadowsocks-AEAD")
	}
	if sent.remote != &clientAddr {
		t.Errorf("Address mismatch: %v != %v", sent.remote, clientAddr)
	}
	// targetConn should be scheduled to close after the full timeout.
	assertAlmostEqual(t, targetConn.deadline, time.Now().Add(timeout))
}

func TestNATNoFastClose_MultipleDNS(t *testing.T) {
	clientConn, targetConn, entry := setupNAT()

	// Send two DNS packets.
	query1 := []byte{1}
	entry.WriteTo(query1, &dnsAddr)
	<-targetConn.send
	query2 := []byte{2}
	entry.WriteTo(query2, &dnsAddr)
	<-targetConn.send

	// Send a response.
	response := []byte{1, 2, 3, 4, 5}
	received := packet{remote: &dnsAddr, payload: response}
	targetConn.recv <- received
	<-clientConn.send

	// targetConn should be scheduled to close after the DNS timeout.
	assertAlmostEqual(t, targetConn.deadline, time.Now().Add(17*time.Second))
}

// Implements net.Error
type fakeTimeoutError struct {
	error
}

func (e *fakeTimeoutError) Timeout() bool {
	return true
}

func (e *fakeTimeoutError) Temporary() bool {
	return false
}

func TestNATTimeout(t *testing.T) {
	_, targetConn, entry := setupNAT()

	// Simulate a non-DNS initial packet.
	entry.WriteTo([]byte{1}, &targetAddr)
	<-targetConn.send
	// Simulate a read timeout.
	received := packet{err: &fakeTimeoutError{}}
	before := time.Now()
	targetConn.recv <- received
	// Wait for targetConn to close.
	if _, ok := <-targetConn.send; ok {
		t.Error("targetConn should be closed due to read timeout")
	}
	// targetConn should be closed as soon as the timeout error is received.
	assertAlmostEqual(t, before, time.Now())
}

func TestNATMultipleProxyIPs(t *testing.T) {
	nat := newNATmap(timeout, &natTestMetrics{}, &sync.WaitGroup{})
	clientConn := makePacketConn()
	targetConn1 := makePacketConn()
	nat.Add(&clientAddr, proxyIP, clientConn, natCipher, targetConn1, "ZZ", "key id")
	entry1 := nat.Get(&clientAddr, proxyIP)
	targetConn2 := makePacketConn()
	proxyIP2 := net.ParseIP("192.0.2.123")
	nat.Add(&clientAddr, proxyIP2, clientConn, natCipher, targetConn2, "ZZ", "key id")
	entry2 := nat.Get(&clientAddr, proxyIP2)

	// Send a standard packet on entry 1.
	entry1.WriteTo([]byte{1}, &targetAddr)
	assertAlmostEqual(t, targetConn1.deadline, time.Now().Add(timeout))
	<-targetConn1.send

	// Send a DNS packet on entry 2.
	entry2.WriteTo([]byte{2}, &dnsAddr)
	// DNS-only connections have a fixed timeout of 17 seconds.
	assertAlmostEqual(t, targetConn2.deadline, time.Now().Add(17*time.Second))
	<-targetConn2.send

	// Send a reply on entry 1 and verify that it is sent from `proxyIP`.
	targetConn1.recv <- packet{&targetAddr, nil, []byte{3}, nil}
	ss1, ok := <-clientConn.send
	if !ok {
		t.Error("clientConn was closed")
	}
	if len(ss1.payload) <= 1 {
		t.Error("Packet is too short to be shadowsocks-AEAD")
	}
	if ss1.remote != &clientAddr {
		t.Errorf("Address mismatch: %v != %v", ss1.remote, clientAddr)
	}
	if !proxyIP.Equal(ss1.local) {
		t.Errorf("Mismatched proxy IP: %v != %v", ss1.local, proxyIP)
	}
	// `targetConn1` is not DNS, so it's still open.
	assertAlmostEqual(t, targetConn1.deadline, time.Now().Add(timeout))

	// Send a reply on entry 2 and verify that it is sent from `proxyIP2`.
	targetConn2.recv <- packet{&dnsAddr, nil, []byte{4}, nil}
	ss2, ok := <-clientConn.send
	if !ok {
		t.Error("clientConn was closed")
	}
	if len(ss2.payload) <= 1 {
		t.Error("Packet is too short to be shadowsocks-AEAD")
	}
	if ss2.remote != &clientAddr {
		t.Errorf("Address mismatch: %v != %v", ss2.remote, clientAddr)
	}
	if !proxyIP2.Equal(ss2.local) {
		t.Errorf("Mismatched proxy IP: %v != %v", ss2.local, proxyIP)
	}
	// `targetConn2`` should be scheduled to close immediately.
	assertAlmostEqual(t, targetConn2.deadline, time.Now())
}

// Simulates receiving invalid UDP packets on a server with 100 ciphers.
func BenchmarkUDPUnpackFail(b *testing.B) {
	cipherList, err := MakeTestCiphers(ss.MakeTestSecrets(100))
	if err != nil {
		b.Fatal(err)
	}
	testPayload := ss.MakeTestPayload(50)
	textBuf := make([]byte, serverUDPBufferSize)
	testIP := net.ParseIP("192.0.2.1")
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		findAccessKeyUDP(testIP, textBuf, testPayload, cipherList)
	}
}

// Simulates receiving valid UDP packets from 100 different users, each with
// their own cipher and IP address.
func BenchmarkUDPUnpackRepeat(b *testing.B) {
	const numCiphers = 100 // Must be <256
	cipherList, err := MakeTestCiphers(ss.MakeTestSecrets(numCiphers))
	if err != nil {
		b.Fatal(err)
	}
	testBuf := make([]byte, serverUDPBufferSize)
	packets := [numCiphers][]byte{}
	ips := [numCiphers]net.IP{}
	snapshot := cipherList.SnapshotForClientIP(nil)
	for i, element := range snapshot {
		packets[i] = make([]byte, 0, serverUDPBufferSize)
		plaintext := ss.MakeTestPayload(50)
		packets[i], err = ss.Pack(make([]byte, serverUDPBufferSize), plaintext, element.Value.(*CipherEntry).Cipher)
		if err != nil {
			b.Error(err)
		}
		ips[i] = net.IPv4(192, 0, 2, byte(i))
	}
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		cipherNumber := n % numCiphers
		ip := ips[cipherNumber]
		packet := packets[cipherNumber]
		_, _, _, err := findAccessKeyUDP(ip, testBuf, packet, cipherList)
		if err != nil {
			b.Error(err)
		}
	}
}

// Simulates receiving valid UDP packets from 100 different IP addresses,
// all using the same cipher.
func BenchmarkUDPUnpackSharedKey(b *testing.B) {
	cipherList, err := MakeTestCiphers(ss.MakeTestSecrets(1)) // One widely shared key
	if err != nil {
		b.Fatal(err)
	}
	testBuf := make([]byte, serverUDPBufferSize)
	plaintext := ss.MakeTestPayload(50)
	snapshot := cipherList.SnapshotForClientIP(nil)
	cipher := snapshot[0].Value.(*CipherEntry).Cipher
	packet, err := ss.Pack(make([]byte, serverUDPBufferSize), plaintext, cipher)
	if err != nil {
		b.Fatal(err)
	}

	const numIPs = 100 // Must be <256
	ips := [numIPs]net.IP{}
	for i := 0; i < numIPs; i++ {
		ips[i] = net.IPv4(192, 0, 2, byte(i))
	}
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		ip := ips[n%numIPs]
		_, _, _, err := findAccessKeyUDP(ip, testBuf, packet, cipherList)
		if err != nil {
			b.Error(err)
		}
	}
}

func TestUDPDoubleServe(t *testing.T) {
	cipherList, err := MakeTestCiphers(ss.MakeTestSecrets(1))
	if err != nil {
		t.Fatal(err)
	}
	testMetrics := &natTestMetrics{}
	const testTimeout = 200 * time.Millisecond
	s := NewUDPService(testTimeout, cipherList, testMetrics)

	c := make(chan error)
	for i := 0; i < 2; i++ {
		go func() {
			err := s.Serve(makePacketConn())
			if err != nil {
				c <- err
				close(c)
			}
		}()
	}

	err = <-c
	if err == nil {
		t.Error("Expected an error from one of the two Serve calls")
	}

	if err := s.Stop(); err != nil {
		t.Error(err)
	}
}

func TestUDPEarlyStop(t *testing.T) {
	cipherList, err := MakeTestCiphers(ss.MakeTestSecrets(1))
	if err != nil {
		t.Fatal(err)
	}
	testMetrics := &natTestMetrics{}
	const testTimeout = 200 * time.Millisecond
	s := NewUDPService(testTimeout, cipherList, testMetrics)

	if err := s.Stop(); err != nil {
		t.Error(err)
	}
	if err := s.Serve(makePacketConn()); err != nil {
		t.Error(err)
	}
}
