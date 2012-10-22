// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cookiejar

import (
	"testing"
)

var domainRuleMatchTests = []struct {
	rule   domainRule
	domain string
	match  bool
}{
	{domainRule{"", 0}, "foo.com", true},
	{domainRule{"foo", 0}, "foo.com", true},
	{domainRule{"bar.foo", 0}, "foo.com", false},
	{domainRule{"", 0}, "bar.foo.com", true},
	{domainRule{"foo", 0}, "bar.foo.com", true},
	{domainRule{"", 2}, "abc.net", true},
	{domainRule{"xyz", 0}, "abc.net", false},
	{domainRule{"abc", 1}, "abc.net", true},
	{domainRule{"foo.abc", 1}, "abc.net", false},
	{domainRule{"city.kyoto", 1}, "www.city.kyoto.jp", true},
	{domainRule{"kyoto", 2}, "www.city.kyoto.jp", true},
	{domainRule{"kyoto", 2}, "kyoto.jp", true},
	{domainRule{"uk", 0}, "uk.com", true},
}

func TestDomainRuleMatch(t *testing.T) {
	for i, tt := range domainRuleMatchTests {
		m := tt.rule.match(tt.domain)
		if m != tt.match {
			t.Errorf("%d: rule=%v, domain=%q, got %t, want %t",
				i, tt.rule, tt.domain, m, tt.match)
		}
	}
}

var findDomainRuleTests = []struct {
	domain string
	rule   *domainRule
}{
	{"notlisted", nil},
	{"really.not.listed", nil},
	{"biz", &domainRule{"", 0}},
	{"domain.biz", &domainRule{"", 0}},
	{"a.b.domain.biz", &domainRule{"", 0}},
	{"com", &domainRule{"", 0}},
	{"example.com", &domainRule{"", 0}},
	{"uk.com", &domainRule{"uk", 0}},
	{"example.uk.com", &domainRule{"uk", 0}},
	{"city.kobe.jp", &domainRule{"city.kobe", 1}},
	{"www.city.kobe.jp", &domainRule{"city.kobe", 1}},
}

func rulesEqual(r1, r2 *domainRule) bool {
	if r1 == nil && r2 == nil {
		return true
	}
	if (r1 != nil && r2 == nil) || (r1 == nil && r2 != nil) {
		return false
	}
	return r1.rule == r2.rule && r1.kind == r2.kind
}

func TestFindDomainRule(t *testing.T) {
	for i, tt := range findDomainRuleTests {
		rule := findDomainRule(tt.domain)
		if !rulesEqual(rule, tt.rule) {
			t.Errorf("%d: %q got %v want %v", i, tt.domain, *rule, *tt.rule)
		}
	}
}

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
			t.Errorf("%d. domain=%q: got %q, want %q. rule was %v]",
				i, tt.domain, etldp1, tt.etldp1, findDomainRule(tt.domain))
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
