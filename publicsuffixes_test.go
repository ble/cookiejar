// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cookiejar

import (
	// "fmt"
	// "math/rand"
	// "reflect"
	"testing"
	"strings"
)

var domainRuleMatchTests = []struct {
	rule domainRule
	domain string
	match        bool
}{
	{domainRule{"",0}, "foo.com", true},
	{domainRule{"foo",0}, "foo.com", true},
	{domainRule{"bar.foo",0}, "foo.com", false},
	{domainRule{"",0}, "bar.foo.com", true},
	{domainRule{"foo",0}, "bar.foo.com", true},
	{domainRule{"", 2}, "abc.net", true},
	{domainRule{"xyz",0}, "abc.net", false},
	{domainRule{"abc",1}, "abc.net", true},
	{domainRule{"foo.abc",1}, "abc.net", false},
	{domainRule{"city.kyoto",1}, "www.city.kyoto.jp", true},
	{domainRule{"kyoto",2}, "www.city.kyoto.jp", true},
	{domainRule{"kyoto",2}, "kyoto.jp", true},
	{domainRule{"uk",0}, "uk.com", true},
}

func TestDomainRuleMatch(t *testing.T) {
	for i, test := range domainRuleMatchTests {
		domain := test.domain[:strings.LastIndex(test.domain,".")]
		m := test.rule.match(domain)
		if m != test.match {
			t.Errorf("%d: Rule %v, domain %s got %t want %t", 
				i, test.rule, test.domain, m, test.match)
		}
	}
}

var findDomainRuleTests = []struct{
	domain string
	rule *domainRule
} {
	{"notlisted", nil},
	{"really.not.listed", nil},
	{"biz", &domainRule{"",0}},
	{"domain.biz", &domainRule{"",0}},
	{"a.b.domain.biz", &domainRule{"",0}},
	{"com", &domainRule{"",0}},
	{"example.com", &domainRule{"",0}},
	{"uk.com", &domainRule{"uk",0}},
	{"example.uk.com", &domainRule{"uk",0}},
	{"pref.kyoto.jp", &domainRule{"pref.kyoto",1}},
	{"www.pref.kyoto.jp", &domainRule{"pref.kyoto",1}},
}

func rulesEqual(r1, r2 *domainRule) bool {
	if r1== nil && r2==nil {
		return true
	}
	if (r1!=nil && r2==nil) || (r1==nil && r2!=nil) {
		return false
	}
	return r1.rule==r2.rule && r1.kind==r2.kind
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

var infoTests = []struct {
	domain         string
	covered, allow bool
	etld           string
}{
	{"something.strange", false, false, "--"},
	{"ourintranet", false, false, "--"},
	{"com", true, false, "--"},
	{"google.com", true, true, "google.com"},
	{"www.google.com", true, true, "google.com"},
	{"uk", true, false, "--"},
	{"co.uk", true, false, "--"},
	{"bbc.co.uk", true, true, "bbc.co.uk"},
	{"foo.www.bbc.co.uk", true, true, "bbc.co.uk"},
}
/***
func TestInfo(t *testing.T) {
	for _, test := range infoTests {
		gc, ga, ge := publicsuffixRules.info(test.domain)
		if gc != test.covered {
			t.Errorf("Domain %s expected coverage %t", test.domain, test.covered)
		} else if gc {
			if ga != test.allow {
				t.Errorf("Domain %s expected allow %t", test.domain, test.allow)
			} else if ga {
				if ge != test.etld {
					t.Errorf("Domain %s expected etld %s got %s",
						test.domain, test.etld, ge)
				}
			}
		}
	}
}
*****/



/*******
func TestRuleCache(t *testing.T) {
	theRuleCache = ruleCache{make([]cacheEntry, 2), 0}
	a := theRuleCache.Lookup("a.com")
	if a != nil {
		t.Errorf("Got %v", *a)
	}
	theRuleCache.Store("a.com", []string{"a"})

	b := theRuleCache.Lookup("b.com")
	if b != nil {
		t.Errorf("Got %v", *b)
	}
	theRuleCache.Store("b.com", []string{"b"})

	a = theRuleCache.Lookup("a.com")
	if a == nil || []string(*a)[0] != "a" {
		t.Errorf("Bad a")
	}
	b = theRuleCache.Lookup("b.com")
	if b == nil || []string(*b)[0] != "b" {
		t.Errorf("Bad b")
	}

	c := theRuleCache.Lookup("c.com")
	if c != nil {
		t.Errorf("Got %v", *c)
	}
	theRuleCache.Store("c.com", []string{"c"})

	a = theRuleCache.Lookup("a.com")
	if a != nil {
		t.Errorf("Got %v\n%v", *a, theRuleCache)
	}
	b = theRuleCache.Lookup("b.com")
	if b == nil || []string(*b)[0] != "b" {
		t.Errorf("Bad b")
	}
	c = theRuleCache.Lookup("c.com")
	if c == nil || []string(*c)[0] != "c" {
		t.Errorf("Bad c")
	}

}
*******/

