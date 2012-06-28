// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cookiejar

import (
	"strings"
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
	for i, test := range domainRuleMatchTests {
		domain := test.domain[:strings.LastIndex(test.domain, ".")]
		m := test.rule.match(domain)
		if m != test.match {
			t.Errorf("%d: Rule %v, domain %s got %t want %t",
				i, test.rule, test.domain, m, test.match)
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
	{"pref.kyoto.jp", &domainRule{"pref.kyoto", 1}},
	{"www.pref.kyoto.jp", &domainRule{"pref.kyoto", 1}},
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
	for i, test := range findDomainRuleTests {
		rule := findDomainRule(test.domain)
		if !rulesEqual(rule, test.rule) {
			t.Errorf("%d: %q got %v want %v", i, test.domain, rule, test.rule)
		}
	}
}

// test case table derived from http://publicsuffix.org/list/test.txt
var effectiveTldPlusOneTests = []struct {
	domain string
	etldp1 string // etldp1=="" iff domain is public suffix 
}{
	/***** We never use empty or mixed cases or leading dots *****
	// NULL input.
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
	{"example.example", ""},
	{"b.example.example", ""},
	{"a.b.example.example", ""},

	/******* These seem to be no longer listed.... **********
	// Listed, but non-Internet, TLD.
	{"local", ""},
	{"example.local", ""},     
	{"b.example.local", ""},   
	{"a.b.example.local", ""}, 
	*********************************************************/

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
	{"c.kyoto.jp", ""},
	{"b.c.kyoto.jp", "b.c.kyoto.jp"},
	{"a.b.c.kyoto.jp", "b.c.kyoto.jp"},
	{"pref.kyoto.jp", "pref.kyoto.jp"},     // Exception rule.
	{"www.pref.kyoto.jp", "pref.kyoto.jp"}, // Exception rule.
	{"city.kyoto.jp", "city.kyoto.jp"},     // Exception rule.
	{"www.city.kyoto.jp", "city.kyoto.jp"}, // Exception rule.
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

func TestEffectiveTldPlusOne(t *testing.T) {
	for _, test := range effectiveTldPlusOneTests {
		etldp1, tooShort := effectiveTldPlusOne(test.domain)

		if test.etldp1 == "" {
			if !tooShort {
				t.Errorf("Domain %s got %q %t\n[rule %v]",
					test.domain, etldp1, tooShort,
					findDomainRule(test.domain))
			}
		} else if test.etldp1 != etldp1 {
			t.Errorf("Domain %s got %q %t want %q\n[rule %v]",
				test.domain, etldp1, tooShort, test.etldp1,
				findDomainRule(test.domain))
		}
	}
}

var allowCookiesOnTests = []struct {
	domain string
	allow  bool
}{
	{"something.strange", false},
	{"ourintranet", false},
	{"com", false},
	{"google.com", true},
	{"www.google.com", true},
	{"uk", false},
	{"co.uk", false},
	{"bbc.co.uk", true},
	{"foo.www.bbc.co.uk", true},
	{"bar.hokkaido.jp", false},
	{"pref.hokkaido.jp", true},
}

func TestAllowCookiesOn(t *testing.T) {
	for i, test := range allowCookiesOnTests {
		allow := allowCookiesOn(test.domain)
		if allow != test.allow {
			t.Errorf("%d: Domain %q expected %t got %t",
				i, test.domain, test.allow, allow)
		}
	}
}

func TestRuleCache(t *testing.T) {
	theRuleCache = ruleCache{cache: make([]cacheEntry, 2)}

	// Stuff in first a and then b
	a, fa := theRuleCache.lookup("a")
	if fa {
		t.Errorf("Unexpected a got %v", *a)
	}
	theRuleCache.store("a", &domainRule{"a", 0})

	b, fb := theRuleCache.lookup("b")
	if fb {
		t.Errorf("Unexpected b got %v", *b)
	}
	theRuleCache.store("b", &domainRule{"b", 0})

	// look up a and b
	x, fx := theRuleCache.lookup("a")
	if !fx || x.rule != "a" {
		t.Errorf("Bad %v", x)
	}
	x, fx = theRuleCache.lookup("b")
	if !fx || x.rule != "b" {
		t.Errorf("Bad %v", x)
	}

	// look up and stuff in c which overwrites a but keeps b
	c, fc := theRuleCache.lookup("c")
	if fc {
		t.Errorf("Unexpected c got %v", *c)
	}
	theRuleCache.store("c", &domainRule{"c", 0})
	x, fx = theRuleCache.lookup("c")
	if !fx || x.rule != "c" {
		t.Errorf("Bad %v", x)
	}
	a, fa = theRuleCache.lookup("a")
	if fa {
		t.Errorf("Unexpected a got %v", *a)
	}
	x, fx = theRuleCache.lookup("b")
	if !fx || x.rule != "b" {
		t.Errorf("Bad %v", x)
	}
}
