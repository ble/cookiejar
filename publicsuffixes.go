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
)

// Storage for the public suffix rules.
// Currently a list of (splitted and reversed) rules
type psStorage [][]string

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
// TODO: remove covered.
// TODO: do not use domainRev
func (ps psStorage) info(domain string) (covered, allow bool, etdl string) {
	domainRev := splitAndReverse(strings.ToLower(domain))
	rule := ps.rule(domain)
	if len(rule) == 0 {
		// no rule
		etdl = domainRev[0]
		if len(domainRev) > 1 {
			etdl = domainRev[1] + "." + etdl
		}
		return false, false, etdl
	}
	covered = true

	// Disallow cookies for domain if domain is a publicsuffix. 
	// Instead of constructing the publicsuffix: domain==publicsuffix
	// if len(rule) == len(domainRev): All elements of rule match
	// all of domain -> domain==publicsuffix described by rule.
	// The rule cannot be longer (it would not match), so:
	allow = len(rule) < len(domainRev)

	if allow {
		// construct effective TLD = "publicsuffix + 1" 
		for i := 0; i <= len(rule); i++ {
			if i > 0 {
				etdl = "." + etdl
			}
			etdl = domainRev[i] + etdl
		}
	} else {
		etdl = domain
	}

	return
}

// -------------------------------------------------------------------------
// Rule

/*
var rules []struct{tld string; sr []struct{fld []string}} {
	{"com", {"is-an-idiot","is-a-rebulican"}},
	{"jp", {"fukui", "fukui.*", "fukui.!city"}},
}

 domain = abc.xyz.com
 --> tld = com
 rest = abc.xyz (zb. abc.fukui oder city.fukui oder qwe.dfg.fukui
 rev fukui.abc

	3 rule types:
 fixed    jp.fukui
 wildcard jp.fukui.*
 exept    jp.fukui.!city

domain-real  abc.xyz.fukui.jp
domain-reved jp.fukui.xyz.abc

domain-real  abc.city.fukui.jp
domain-reved jp.fukui.city.abc

domain-real  fukui.jp
domain-reved jp.fukui
must not match rule jp.fukuimashi

domain match either:
  - domain == rule   or
  - "." + rule is suffix of domain
works even for wildcard rule if domain does not start with dot.

type Rule {
 typ ruleType
 fld string // the abc in xyz.abc.org
 rest string
}

type Storage {
 tld string
 exceptions []string  // any exeptions collected
 simples, complex []string  ony one is non nil
 }

var rules = []struct{tld string, exeptions []Rule, rules []Rule}}


lookup:
 - binary search for tld (there is exactly one or none, but not multiple)
  - not found --> done
  - linear search in exeptions
  - found --> done
 - binary search on fld (might have several)
  - not found --> done
  - check rest


*/

// 
type Rule []string

type cacheEntry struct {
	domain string
	rule   Rule
}
type ruleCache struct {
	cache []cacheEntry
	idx   int
}

func (rc ruleCache) Lookup(domain string) *Rule {
	for _, e := range rc.cache {
		if e.domain == domain {
			return &e.rule
		}
	}
	return nil
}
func (rc *ruleCache) Store(domain string, rule Rule) {
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

var theRuleCache = ruleCache{make([]cacheEntry, 20), 0}

// find rule in ps best matching domain (given in spliied and reversed form.
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
// Point 2 is cleary wrong: For a domain like "really.not.listed" the default
// rule "*" would be the best matching rule which results in a public suffix
// of "listed" for "really.not.listed" which is not a public suffix.
//
// call with split and reversed domain and get the rule back in same format
func (ps psStorage) rule(domain string) []string {

	if rule := theRuleCache.Lookup(domain); rule != nil {
		return []string(*rule)
	}
	domainRev := splitAndReverse(domain)

	rule := []string{} // (2) but adopted

	var exceptionRule []string
	numLabels := 0

	startIdx, endIdx := ps.tldIndex(domainRev[0])
	if startIdx == -1 {
		return rule
	}
	for i := startIdx; i <= endIdx; i++ { // (1) adopted
		r := publicsuffixRules[i]
		if !ps.ruleMatch(r, domainRev) {
			continue
		}
		if r[len(r)-1][0] == '!' { // (3) found exception rule
			exceptionRule = r[:len(r)-1] // (5) remove leftmost (here last) label
		} else if len(r) > numLabels {
			rule = r // (4)
			numLabels = len(rule)
		}
	}

	if exceptionRule != nil {
		// fmt.Printf("Rule for %v (exception) %v\n", domainRev, exceptionRule)
		theRuleCache.Store(domain, exceptionRule)
		return exceptionRule
	}

	// fmt.Printf("Rule for %v (longest) %v\n", domainRev, rule)
	theRuleCache.Store(domain, rule)
	return rule
}

// Look up range of rules for TLD tld. 
// all rules for tld will be between startIdx and endIdx.
func (ps psStorage) tldIndex(tld string) (startIdx, endIdx int) {
	// binary search to find any rule for tld
	startIdx, endIdx = 0, len(ps)-1
	if ps[startIdx][0] > tld || ps[endIdx][0] < tld {
		return 0, 0
	}
	m := endIdx / 2

	for {
		if ps[m][0] < tld {
			startIdx = m
		} else if ps[m][0] > tld {
			endIdx = m
		} else {
			break
		}
		if endIdx-startIdx < 4 {
			break
		}
		m = (startIdx + endIdx) / 2
		// fmt.Printf("  %d  %d  %d\n", startIdx, m, endIdx)
	}
	// m now lies somewhere in the range of the rules for tld.

	// find better startindex
	x := m
	mm := (startIdx + x) / 2
	for {
		if x-startIdx < 8 {
			break
		}
		if ps[mm][0] < tld {
			startIdx = mm
		} else {
			x = mm
		}
		mm = (startIdx + x) / 2
	}

	// find better endindex
	x = m
	mm = (endIdx + x) / 2
	for {
		if endIdx-x < 8 {
			break
		}
		if ps[mm][0] > tld {
			endIdx = mm
		} else {
			x = mm
		}
		mm = (endIdx + x) / 2
	}

	return
}

// From http://publicsuffix.org/list/:
// A domain is said to match a rule if, when the domain and rule are both 
// split,and one compares the labels from the rule to the labels from the 
// domain, beginning at the right hand end, one finds that for every pair 
// either they are identical, or that the label from the rule is "*" (star).
// The domain may legitimately have labels remaining at the end of this 
// matching process.
func (ps psStorage) ruleMatch(rule, domain []string) bool {
	lastInDomain := len(domain) - 1
	for i, label := range rule {
		if i > lastInDomain {
			// didn't match whole rule
			return false
		}
		if label[0] == '!' {
			label = label[1:] // strip exception identification for match
		}
		if label != domain[i] && label != "*" {
			return false
		}
	}
	return true
}

// "www.example.com"  -->  {"com", "example", "www"}
func splitAndReverse(domain string) []string {
	forward := strings.Split(domain, ".")
	n := len(forward)
	backward := make([]string, n)
	for i := 0; i < n; i++ {
		backward[i] = forward[n-1-i]
	}
	return backward
}
