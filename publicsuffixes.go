// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cookiejar

// The public suffix stuff tries to answer the question:
// "Should we allow to set a domain cookie for domain d?"
// It also contains code to calculate the "effective top
// level domain plus one" (etldp1) which are the registered
// or registrable domains.
// See http://publicsuffix.org/ for details.

import (
	"fmt"
	"strings"
)

var _ = fmt.Printf

// domainRule (together with a TLD) describes one rule in the list
type domainRule struct {
	rule string // the original rule stripped from tld, "!" and "*"
	kind ruleKind
}

type ruleKind uint8

const (
	normalRule ruleKind = iota
	exceptionRule
	wildcardRule
)

// match decides if the rule r would match domain.
//
// From http://publicsuffix.org/list/:
// A domain is said to match a rule if, when the domain and rule are both
// split,and one compares the labels from the rule to the labels from the
// domain, beginning at the right hand end, one finds that for every pair
// either they are identical, or that the label from the rule is "*" (star).
// The domain may legitimately have labels remaining at the end of this
// matching process.
//
func (r *domainRule) match(domain string) bool {
	// Strip TLD from domain as rules are stored without TLD:
	if i := strings.LastIndex(domain, "."); i != -1 {
		domain = domain[:i]
	}

	if !strings.HasSuffix(domain, r.rule) {
		return false //  rule: xyz.tld  domain: abc.tld
	}
	if len(domain) == len(r.rule) {
		return true // rule: abc.tld  domain: abc.tld
	}
	// from here on: domain is longer than rule
	if len(r.rule) == 0 || domain[len(domain)-len(r.rule)-1] == '.' {
		return true // rule: abc.tld  domain: xyz.abc.tld
	}

	return false // rule: abc.tld  domain aaabc.tld
}

// effectiveTldPlusOne retrieves TLD + 1 respective the publicsuffix + 1.
// For domains which are too short (tld ony, or publixsuffix only)
// the empty string is returned.
//
func EffectiveTLDPlusOne(domain string) string {
	// Algorithm
	//    6. The public suffix is the set of labels from the domain which directly
	//       match the labels of the prevailing rule (joined by dots).
	//    7. The registered or registrable domain is the public suffix plus one
	//       additional label.
	rule := findDomainRule(domain)
	// fmt.Printf("  rule for %s = %v\n", domain, rule)
	labels := strings.Split(domain, ".")
	var n int
	if rule == nil {
		// no rule from our list matches: default rule is "*"
		n = 2
	} else {
		if rule.rule == "" {
			n = 2
		} else {
			// +1 to get from . to parts, +1 as tld itself is
			// stripped from r.rule and +1 as we want etld+1
			n = strings.Count(rule.rule, ".") + 3
		}
		if rule.kind == exceptionRule {
			n--
		} else if rule.kind == wildcardRule {
			n++
		}

	}

	if n > len(labels) {
		return ""
	}

	if n < len(labels) {
		return strings.Join(labels[len(labels)-n:], ".")
	}
	return domain
}

// check whether domain is "specific" enough to allow domain cookies
// to be set for this domain.
func allowDomainCookies(domain string) bool {
	// TODO: own algorithm to save unused string gymnastics
	etldp1 := EffectiveTLDPlusOne(domain)
	// fmt.Printf("  etldp1 = %s\n", etldp1)
	return etldp1 != ""
}

// retrieve all necessary information from a psStorage ps.
// covered is true if the domain was covered by a rule; if covered is false
// all other return values are undefined.
// allow indicates wheter to allow a cookie on domain or not.
// etdl is the "effective TLD" for domain, i.e. the domain for which
// cookies may be set. Its the public suffix plus one more label from
// the domain.
// Examples:
//    info("something.strange")  ==  false, --, --
//    info("ourintranet")        ==  false, --, --
//    info("com")                ==  true, false, --
//    info("google.com")         ==  true, true, google.com
//    info("www.google.com")     ==  true, true, google.com
//    info("uk")                 ==  true, false, --
//    info("co.uk")              ==  true, false, --
//    info("bbc.co.uk")          ==  true, true, bbc.co.uk
//    info("foo.www.bbc.co.uk")  ==  true, true, bbc.co.uk
// Algorithm
//    6. The public suffix is the set of labels from the domain which directly 
//       match the labels of the prevailing rule (joined by dots).
//    7. The registered or registrable domain is the public suffix plus one 
//       additional label.
//

// findDomainRule looks up the matching rule in our domainRules list.
//
// Algorithm from http://publicsuffix.org/list/:
//    1. Match domain against all rules and take note of the matching ones.
//    2. If no rules match, the prevailing rule is "*".
//    3. If more than one rule matches, the prevailing rule is the one which
//       is an exception rule.
//    4. If there is no matching exception rule, the prevailing rule is the one
//       with the most labels.
//    5. If the prevailing rule is a exception rule, modify it by removing the
//       leftmost label.
//    6. The public suffix is the set of labels from the domain which directly
//       match the labels of the prevailing rule (joined by dots).
//    7. The registered or registrable domain is the public suffix plus one
//       additional label.
//
// We do not do step 5, this is the callers responsibility.
func findDomainRule(domain string) (rule *domainRule) {
	// extract TLD from domain and look up list of rules for
	// this TLD if present
	var tld string
	if i := strings.LastIndex(domain, "."); i != -1 {
		tld = domain[i+1:]
	} else {
		tld = domain
	}
	rules, ok := domainRules[tld]
	if !ok {
		return nil
	}
	// fmt.Printf("Found %d rules on TLD %s domain=%s\n", len(rules), tld, domain)
	// rules are sorted in presidence, so first match is the match
	rule = nil
	for i := range rules {
		// fmt.Printf("  %d: %v  --> %t\n", i, rules[i], rules[i].match(domain))
		if rules[i].match(domain) {
			rule = &rules[i]
			break
		}
	}

	return rule
}
