// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cookiejar

// Tests for the unexported helper functions.

import (
	"net/url"
	"testing"
)

var defaultPathTests = []struct{ path, dir string }{
	{"", "/"},
	{"xy", "/"},
	{"xy/z", "/"},
	{"/", "/"},
	{"/abc", "/"},
	{"/ab/xy", "/ab"},
	{"/ab/xy/z", "/ab/xy"},
	{"/ab/", "/ab"},
	{"/ab/xy/z/", "/ab/xy/z"},
}

func TestDefaultPath(t *testing.T) {
	for i, tt := range defaultPathTests {
		u := url.URL{Path: tt.path}
		got := defaultPath(&u)
		if got != tt.dir {
			t.Errorf("#%d %q: want %q, got %q", i, tt.path, got, tt.dir)
		}
	}
}

var pathMatchTests = []struct {
	cookiePath string
	urlPath    string
	match      bool
}{
	{"/", "/", true},
	{"/x", "/x", true},
	{"/", "/abc", true},
	{"/abc", "/foo", false},
	{"/abc", "/foo/", false},
	{"/abc", "/abcd", false},
	{"/abc", "/abc/d", true},
	{"/path", "/", false},
	{"/path", "/path", true},
	{"/path", "/path/x", true},
}

func TestPathMatch(t *testing.T) {
	for i, tt := range pathMatchTests {
		c := &Cookie{Path: tt.cookiePath}
		if c.pathMatch(tt.urlPath) != tt.match {
			t.Errorf("#%d want %t for %q ~ %q", i, tt.match, tt.cookiePath, tt.urlPath)
		}
	}
}

var hostTests = []struct {
	in, expected string
}{
	{"www.example.com", "www.example.com"},
	{"www.EXAMPLE.com", "www.example.com"},
	{"wWw.eXAmple.CoM", "www.example.com"},
	{"www.example.com:80", "www.example.com"},
	{"12.34.56.78:8080", "12.34.56.78"},
	// TODO: add IDN testcase
}

func TestHost(t *testing.T) {
	for i, tt := range hostTests {
		out, _ := host(&url.URL{Host: tt.in})
		if out != tt.expected {
			t.Errorf("#%d %q: got %q, want %Q", i, tt.in, out, tt.expected)
		}
	}
}

var isIPTests = []struct {
	host string
	isIP bool
}{
	{"example.com", false},
	{"127.0.0.1", true},
	{"1.1.1.300", false},
	{"www.foo.bar.net", false},
	{"123.foo.bar.net", false},
	// TODO: IPv6 test
}

func TestIsIP(t *testing.T) {
	for i, tt := range isIPTests {
		if isIP(tt.host) != tt.isIP {
			t.Errorf("#%d %q: want %t", i, tt.host, tt.isIP)
		}
	}
}

var domainAndTypeTests = []struct {
	inHost         string
	inCookieDomain string
	outDomain      string
	outHostOnly    bool
}{
	{"www.example.com", "", "www.example.com", true},
	{"127.www.0.0.1", "127.0.0.1", "", false},
	{"www.example.com", ".", "", false},
	{"www.example.com", "..", "", false},
	{"www.example.com", "com", "", false},
	{"www.example.com", ".com", "", false},
	{"www.example.com", "example.com", "example.com", false},
	{"www.example.com", ".example.com", "example.com", false},
	{"www.example.com", "www.example.com", "www.example.com", false},  // Unsure about this and
	{"www.example.com", ".www.example.com", "www.example.com", false}, // this one.
	{"foo.sso.example.com", "sso.example.com", "sso.example.com", false},
}

func TestDomainAndType(t *testing.T) {
	jar := Jar{}
	for i, tt := range domainAndTypeTests {
		d, h, _ := jar.domainAndType(tt.inHost, tt.inCookieDomain)
		if d != tt.outDomain || h != tt.outHostOnly {
			t.Errorf("#%d %q/%q: want %q/%t got %q/%t",
				i, tt.inHost, tt.inCookieDomain,
				tt.outDomain, tt.outHostOnly, d, h)
		}
	}
}
