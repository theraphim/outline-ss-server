// Copyright 2019 The Outline Authors
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

package ipset

import (
	"context"
	"math/rand"
	"net"
	"sync"
)

// IPSet represents an unordered collection of IP addresses for a single host.
// One IP can be marked as confirmed to be working correctly.
type IPSet struct {
	mu        sync.RWMutex
	ips       []net.IP      // All known IPs for the server.
	confirmed net.IP        // IP address confirmed to be working
	r         *net.Resolver // Resolver to use for hostname resolution
}

// SetResolver allows use of a custom resolver for IPSet.Add().
func (s *IPSet) SetResolver(r *net.Resolver) {
	s.mu.Lock()
	s.r = r
	s.mu.Unlock()
}

// Reports whether ip is in the set.  Must be called under RLock.
func (s *IPSet) has(ip net.IP) bool {
	for _, oldIP := range s.ips {
		if oldIP.Equal(ip) {
			return true
		}
	}
	return false
}

// Adds an IP to the set if it is not present.  Must be called under Lock.
func (s *IPSet) add(ip net.IP) {
	if !s.has(ip) {
		s.ips = append(s.ips, ip)
	}
}

// Add one or more IP addresses to the set.
// The hostname can be a domain name or an IP address.
func (s *IPSet) Add(hostname string) error {
	// Don't hold the ipMap lock during blocking I/O.
	resolved, err := s.r.LookupIPAddr(context.TODO(), hostname)
	if err != nil {
		return err
	}
	s.mu.Lock()
	for _, addr := range resolved {
		s.add(addr.IP)
	}
	s.mu.Unlock()
	return nil
}

// Empty reports whether the set is empty.
func (s *IPSet) Empty() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.ips) == 0
}

// GetAll returns a copy of the IP set as a slice in random order.
// The slice is owned by the caller, but the elements are owned by the set.
func (s *IPSet) GetAll() []net.IP {
	s.mu.RLock()
	c := append([]net.IP{}, s.ips...)
	s.mu.RUnlock()
	rand.Shuffle(len(c), func(i, j int) {
		c[i], c[j] = c[j], c[i]
	})
	return c
}

// Confirmed returns the confirmed IP address, or nil if there is no such address.
func (s *IPSet) Confirmed() net.IP {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.confirmed
}

// Confirm marks ip as the confirmed address.
func (s *IPSet) Confirm(ip net.IP) {
	// Optimization: Skip setting if it hasn't changed.
	if ip.Equal(s.Confirmed()) {
		// This is the common case.
		return
	}
	s.mu.Lock()
	// has() is O(N)
	if s.has(ip) {
		s.confirmed = ip
	}
	s.mu.Unlock()
}

func (s *IPSet) AddAndConfirm(ip net.IP) {
	// Optimization: Skip setting if it hasn't changed.
	if ip.Equal(s.Confirmed()) {
		// This is the common case.
		return
	}
	s.mu.Lock()
	// Add is O(N)
	s.add(ip)
	s.confirmed = ip
	s.mu.Unlock()
}

// Disconfirm sets the confirmed address to nil if the current confirmed address
// is the provided ip.
func (s *IPSet) Disconfirm(ip net.IP) {
	s.mu.Lock()
	if ip.Equal(s.confirmed) {
		s.confirmed = nil
	}
	s.mu.Unlock()
}
