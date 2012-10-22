// Copyright 2012 Volker Dobler. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cookiejar

// Tests for the unexported helper functions.

import (
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"
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

var flatCleanupTests = []struct {
	spec string // E: expired cookie at this position in flat slice
	exp  string // expected order of cookies after cleanup
}{
	{"vvvvv", "01234"},
	{"vvvvE", "0123"},
	{"vvvEE", "012"},
	{"Evvvv", "4123"},
	{"EEvvv", "432"},
	{"EvEvv", "413"},
	{"EvEvE", "31"},
	{"EvEEE", "1"},
	{"EEEvv", "43"},
	{"EEEvE", "3"},
	{"EEEEE", ""},
	{"EEEvvEEE", "43"},
	{"EEvEvEEE", "42"},
	{"EEvEvvEE", "542"},
	{"EEvEEvEE", "52"},
	{"vvEEEEEE", "01"},
}

func TestFlatCleanup(t *testing.T) {
	past := time.Now().Add(-1 * time.Hour)
	generate := func(spec string) *flat {
		// turn a spec into a flat slice
		f := make(flat, len(spec))
		for i := range spec {
			name := fmt.Sprintf("%d", i) // name is index in original slice
			cookie := Cookie{Name: name}
			if spec[i] == 'E' {
				cookie.Expires = past
			}
			f[i] = &cookie
		}
		return &f
	}

	for i, tt := range flatCleanupTests {
		fp := generate(tt.spec)
		fp.cleanup(strings.Count(tt.spec, "E"))
		s := ""
		for i := range *fp {
			s += (*fp)[i].Name
		}
		if s != tt.exp {
			t.Errorf("%d %s: Want %q, got %q", i, tt.spec, tt.exp, s)
		}
	}

}
