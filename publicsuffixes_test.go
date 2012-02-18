// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cookiejar

import (
	"fmt"
	"math/rand"
	"reflect"
	"testing"
	// "strings"
)

var ruleMatchTests = []struct {
	rule, domain string
	match        bool
}{
	{"com", "foo.com", true},
	{"foo.com", "foo.com", true},
	{"bar.foo.com", "foo.com", false},
	{"com", "bar.foo.com", true},
	{"foo.com", "bar.foo.com", true},
	{"net", "foo.com", false},
	{"net", "net.foo.com", false},
	{"*.net", "abc.net", true},
	{"xyz.net", "abc.net", false},
	{"!abc.net", "abc.net", true},
	{"!foo.abc.net", "abc.net", false},
}

func TestRuleMatch(t *testing.T) {
	for _, test := range ruleMatchTests {
		domainRev := splitAndReverse(test.domain)
		rule := splitAndReverse(test.rule)
		if publicsuffixRules.ruleMatch(rule, domainRev) != test.match {
			t.Errorf("Rule %s, domain %s got want %t", test.rule, test.domain, test.match)
		}
	}
}

var ruleTests = []struct{ domain, rule string }{
	{"foo.com", "com"},
	{"foo.bar.jm", "*.jm"},
	{"bar.jm", "*.jm"},
	{"foo.bar.hokkaido.jp", "*.hokkaido.jp"},
	{"bar.hokkaido.jp", "*.hokkaido.jp"},
	{"pref.hokkaido.jp", "hokkaido.jp"},
}

func TestRule(t *testing.T) {
	for _, test := range ruleTests {
		domainRev := splitAndReverse(test.domain)
		trr := splitAndReverse(test.rule)
		rule := publicsuffixRules.rule(domainRev)

		if !reflect.DeepEqual(rule, trr) {
			t.Errorf("Test %s got %v want %v", test.domain, rule, trr)
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

// test case table derived from http://publicsuffix.org/list/test.txt
// which justifies the strong format
var publicsuffixTests = []struct {
	domain string
	etld   string // etld=="" iff domain is public suffix or _not_ covered   
}{
	/***** We never use empty or mixed cases or leading dots 
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
	*********************************************************/
	// Unlisted TLD.
	{"example", ""},
	{"example.example", ""},
	{"b.example.example", ""},
	{"a.b.example.example", ""},
	// Listed, but non-Internet, TLD.
	{"local", ""},
	/*
	 {"example.local", ""},     // probably wrong testcases here: There is
	 {"b.example.local", ""},   // there is a lone rule "local" in the list
	 {"a.b.example.local", ""}, // so "local" is a ps, but example.local ist not.
	*/
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

func TestPublicsuffix(t *testing.T) {
	for _, test := range publicsuffixTests {
		covered, allowed, etld := publicsuffixRules.info(test.domain)
		if test.etld != "" {
			if !covered || !allowed || etld != test.etld {
				t.Errorf("Domain %s got %t %t %s want true true %s",
					test.domain, covered, allowed, etld, test.etld)
			}
		} else {
			// Too bad test data does not allow to distinguish
			// "not covered" from "disallowed by matching rule"
			if covered && allowed {
				t.Errorf("Domain %s got (covered and allowed)", test.domain)
			}
		}
	}
}

func BenchmarkRule(b *testing.B) {
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		n := rand.Intn(len(publicsuffixRules))
		domain := publicsuffixRules[n]
		last := len(domain) - 1
		if domain[last][0] == '!' {
			domain[last] = domain[last][1:]
		} else if domain[last] == "*" {
			domain[last] = "anything"
		}
		b.StartTimer()

		r := publicsuffixRules.rule(domain)

		if !reflect.DeepEqual(r, publicsuffixRules[n]) {
			fmt.Sprintf("Oops: %v %v", r, publicsuffixRules[n])
		}
	}
}
