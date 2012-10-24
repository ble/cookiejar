// Copyright 2012 Volker Dobler. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cookiejar

import (
	"testing"
)

// Test case table derived from
// http://mxr.mozilla.org/mozilla-central/source/netwerk/test/unit/data/test_psl.txt?raw=1
// See http://publicsuffix.org/list/ for details.
var effectiveTLDPlusOneTests = []struct {
	domain string
	etldp1 string
}{
	/***** We never use empty domains, mixed cases or leading dots *****
	// null input.
	{"", ""},
	// Mixed case.
	{"COM", ""},
	{"example.COM", "example.com"},
	{"WwW.example.COM", "example.com"},
	// Leading dot.
	{".com", ""},
	{".example", ""},
	{".example.com", ""},
	{".example.example", ""},
	**************************************************************/

	// Unlisted TLD.

	{"example", ""},
	{"example.example", "example.example"},
	{"b.example.example", "example.example"},
	{"a.b.example.example", "example.example"},

	// Listed, but non-Internet, TLD. (Yes, these are commented out in the original too.)
	// {"local", ""},
	// {"example.local", ""},
	// {"b.example.local", ""},
	// {"a.b.example.local", ""},

	// TLD with only 1 rule.
	{"biz", ""},
	{"domain.biz", "domain.biz"},
	{"b.domain.biz", "domain.biz"},
	{"a.b.domain.biz", "domain.biz"},
	// TLD with some 2-level rules.
	{"com", ""},
	{"example.com", "example.com"},
	{"b.example.com", "example.com"},
	{"a.b.example.com", "example.com"},
	{"uk.com", ""},
	{"example.uk.com", "example.uk.com"},
	{"b.example.uk.com", "example.uk.com"},
	{"a.b.example.uk.com", "example.uk.com"},
	{"test.ac", "test.ac"},
	// TLD with only 1 (wildcard) rule.
	{"cy", ""},
	{"c.cy", ""},
	{"b.c.cy", "b.c.cy"},
	{"a.b.c.cy", "b.c.cy"},
	// More complex TLD.
	{"jp", ""},
	{"test.jp", "test.jp"},
	{"www.test.jp", "test.jp"},
	{"ac.jp", ""},
	{"test.ac.jp", "test.ac.jp"},
	{"www.test.ac.jp", "test.ac.jp"},
	{"kyoto.jp", ""},
	{"test.kyoto.jp", "test.kyoto.jp"},
	{"ide.kyoto.jp", ""},
	{"b.ide.kyoto.jp", "b.ide.kyoto.jp"},
	{"a.b.ide.kyoto.jp", "b.ide.kyoto.jp"},
	{"c.kobe.jp", ""},
	{"b.c.kobe.jp", "b.c.kobe.jp"},
	{"a.b.c.kobe.jp", "b.c.kobe.jp"},
	{"city.kobe.jp", "city.kobe.jp"},

	// TLD with a wildcard rule and exceptions.
	{"om", ""},
	{"test.om", ""},
	{"b.test.om", "b.test.om"},
	{"a.b.test.om", "b.test.om"},
	{"songfest.om", "songfest.om"},
	{"www.songfest.om", "songfest.om"},
	// US K12.
	{"us", ""},
	{"test.us", "test.us"},
	{"www.test.us", "test.us"},
	{"ak.us", ""},
	{"test.ak.us", "test.ak.us"},
	{"www.test.ak.us", "test.ak.us"},
	{"k12.ak.us", ""},
	{"test.k12.ak.us", "test.k12.ak.us"},
	{"www.test.k12.ak.us", "test.k12.ak.us"},
}

func TestEffectiveTLDPlusOneTests(t *testing.T) {
	for i, tt := range effectiveTLDPlusOneTests {
		etldp1 := EffectiveTLDPlusOne(tt.domain)

		if etldp1 != tt.etldp1 {
			t.Errorf("%d. domain=%q: got %q, want %q.",
				i, tt.domain, etldp1, tt.etldp1)
		}
	}
}

var allowCookiesOnTests = []struct {
	domain string
	allow  bool
}{
	{"something.strange", true},
	{"ourintranet", false},
	{"com", false},
	{"google.com", true},
	{"www.google.com", true},
	{"uk", false},
	{"co.uk", false},
	{"bbc.co.uk", true},
	{"foo.www.bbc.co.uk", true},
	{"kawasaki.jp", false},
	{"bar.kawasaki.jp", false},
	{"foo.bar.kawasaki.jp", true},
	{"city.kawasaki.jp", true},
	{"aichi.jp", false},
	{"aisai.aichi.jp", false},
	{"foo.aisai.aichi.jp", true},
}

func TestAllowCookiesOn(t *testing.T) {
	for i, tt := range allowCookiesOnTests {
		allow := allowDomainCookies(tt.domain)
		if allow != tt.allow {
			t.Errorf("%d: domain=%q expected %t got %t", i, tt.domain, tt.allow, allow)
		}
	}
}

func BenchmarkAllowDomainCookies(b *testing.B) {
	for i := 0; i < b.N; i++ {
		for _, tt := range allowCookiesOnTests {
			allowDomainCookies(tt.domain)
		}
	}
}

var unlistedDomains = []string{
	"www.google.ch",
	"www.123abc.com",
	"www.aaaaaaa.com",
	"www.ddddddd.com",
	"www.iiiiiii.com",
	"www.mmmmmmm.net",
	"www.ppppppp.net",
	"www.rrrrrrr.org",
	"www.uuuuuuu.org",
	"www.xxxxxxx.org",
	"www.zzzzzzz.de",
	"www.yyyyyyy.it",
	"www.wwwwwww.jp",
}

func BenchmarkAllowULDomainCookies(b *testing.B) {
	for i := 0; i < b.N; i++ {
		for _, domain := range unlistedDomains {
			allowDomainCookies(domain)
		}
	}
}
