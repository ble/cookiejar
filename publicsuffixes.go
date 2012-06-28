// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cookiejar

// The public suffix stuff tries to answer the following two questions:
// A) "Should we allow to set a domain cookie for domain d?"
// B) "Which key to use while storing/retrieving the cookie?" 
// Question A is for security reasons, question B for efficency.

import (
	"strings"
	"sync"
)

// domainRule (together with a TLD) describes one rule
type domainRule struct {
	rule string // the original rule stripped from tld, "!" and "*"
	kind uint8  // 0: normal, 1: exception, 2: wildcard
}

// match decides if the rule r would match domain.
// As rules are strored without TLD the domain must be provided
// too with the TLD removed.
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
	if !strings.HasSuffix(domain, r.rule) {
		// fmt.Printf("%v.match(%q) -->  false, no suffix\n", *r, domain)
		return false //  rule: xyz.tld  domain: abc.tld
	}
	if len(domain) == len(r.rule) {
		/******
		if r.kind == 2 {
			fmt.Printf("%v.match(%q) -->  false, missing *\n", *r, domain)
			return false  // rule: *.abc.tld  domain: abc.tld
		}
		 ********/
		// fmt.Printf("%v.match(%q) -->  true1\n", *r, domain)
		return true // rule: abc.tld  domain: abc.tld
	}
	// from here on: domain is longer than rule
	if len(r.rule) == 0 || domain[len(domain)-len(r.rule)-1] == '.' {
		// fmt.Printf("%v.match(%q) -->  true2 \n", *r, domain)
		return true // rule: abc.tld  domain: xyz.abc.tld
	}

	// fmt.Printf("%v.match(%q) -->  false %c\n", *r, domain, domain[len(domain)-len(r.rule)-1])
	return false // rule: abc.tld  domain aaabc.tld
}

// effectiveTldPlusOne retrieves TLD + 1 respective the publicsuffix + 1.
// For domains which are too short (tld ony, or publixsuffix only)
// domain itself is returned and the fact is reported with tooShort==true
//
// Algorithm
//    6. The public suffix is the set of labels from the domain which directly 
//       match the labels of the prevailing rule (joined by dots).
//    7. The registered or registrable domain is the public suffix plus one 
//       additional label.
func effectiveTldPlusOne(domain string) (etldp1 string, tooShort bool) {
	rule := findDomainRule(domain)
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
		if rule.kind == 1 {
			n-- // expection rule
		} else if rule.kind == 2 {
			n++ // wildcard rule
		}

	}

	if n > len(labels) {
		n = len(labels) // cannot return more than we have
		tooShort = true
	}
	etldp1 = strings.Join(labels[len(labels)-n:], ".")
	return etldp1, tooShort
}

// check whether domain is "specific" enough to allow domain cookies
// to be set for this domain.
func allowCookiesOn(domain string) bool {
	_, tooShort := effectiveTldPlusOne(domain) // TODO: own algorithm to save unused string gymnastics
	return !tooShort
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

// -------------------------------------------------------------------------
// A cache for domainRules to speed up lookup

type cacheEntry struct {
	domain string
	rule   *domainRule
}
type ruleCache struct {
	cache []cacheEntry
	idx   int
	lock  sync.RWMutex
}

// lookup returns the rule, true if found or nil, false if not found
func (rc ruleCache) lookup(domain string) (*domainRule, bool) {
	rc.lock.RLock()
	defer rc.lock.RUnlock()

	for _, e := range rc.cache {
		if e.domain == domain {
			return e.rule, true
		}
	}
	return nil, false
}

// remember rule (which might be nil) for domain
func (rc *ruleCache) store(domain string, rule *domainRule) {
	rc.lock.Lock()
	defer rc.lock.Unlock()

	if rc.idx == len(rc.cache) {
		rc.cache = append(rc.cache, cacheEntry{domain, rule})
	} else {
		rc.cache[rc.idx] = cacheEntry{domain, rule}
	}
	rc.idx++
	if rc.idx == cap(rc.cache) {
		rc.idx = 0
	}
}

var theRuleCache = ruleCache{cache: make([]cacheEntry, 40), idx: 0}

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
	if rule, found := theRuleCache.lookup(domain); found {
		return rule
	}

	// extract TLD from domain and look up list of rules for 
	// this TLD if present
	var tld string
	var strippedDomain string
	if i := strings.LastIndex(domain, "."); i != -1 {
		tld = domain[i+1:]
		strippedDomain = domain[:i]
	} else {
		tld = domain
		strippedDomain = ""
	}
	rules, ok := domainRules[tld]
	if !ok {
		return nil
	}

	// rules are sorted in presidence, so first match is the match
	rule = nil
	for i := range rules {
		if rules[i].match(strippedDomain) {
			rule = &rules[i]
			break
		}
	}

	theRuleCache.store(domain, rule)

	return rule
}
