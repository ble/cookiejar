// Copyright 2012 Volker Dobler. All rights reserved.
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

type Rule uint8

const (
	None Rule = iota // not a rule, just internal node
	Normal
	Exception
	Wildcard
)

type Node struct {
	Label string
	Kind  Rule
	Sub   []Node
}

func findLabel(label string, nodes []Node) *Node {
	// TODO replace with binary search
	for i := range nodes {
		if nodes[i].Label == label {
			return &nodes[i]
		}
	}
	return nil
}

func EffectiveTLDPlusOne(domain string) (ret string) {
	fmt.Println(domain)
	parts := strings.Split(domain, ".")
	m := len(parts)
	nodes := PublicSuffixes.Sub
	var np *Node
	for m > 0 {
		m--
		fmt.Printf("  m=%d  looking for %s\n", m, parts[m])
		sub := findLabel(parts[m], nodes)
		if sub == nil {
			fmt.Printf("    not found\n")
			m++
			break
		}
		fmt.Printf("    found\n")
		nodes = sub.Sub
		np = sub
	}
	fmt.Printf("    np=%p m=%d\n", np, m)
	// np now points to last matching node

	if np == nil || np.Kind == None {
		// no rule found, default is "*"
		fmt.Printf("  no rule found m=%d (np=%p)\n", m, np)
		if m >= 1 {
			fmt.Printf("  --> m=%d >=1: %s\n", m, parts[m-1]+"."+parts[m])
			return parts[m-1] + "." + parts[m]
		} else {
			fmt.Printf("  --> m=%d <1: ''\n", m)
			return ""
		}
	}

	switch np.Kind {
	case Normal:
		m--
		fmt.Printf("  normal rule m=%d\n", m)
	case Exception:
		fmt.Printf("  exexption rule. m=%d\n", m)
	case Wildcard:
		m -= 2
		fmt.Printf("  wildcard rule. m=%d\n", m)
	}
	if m < 0 {
		fmt.Printf("  --> m<0: ''\n")
		return ""
	}
	fmt.Printf("  --> %s\n", strings.Join(parts[m:], "."))
	return strings.Join(parts[m:], ".")
}

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

// effectiveTldPlusOne retrieves TLD + 1 respective the publicsuffix + 1.
// For domains which are too short (tld ony, or publixsuffix only)
// the empty string is returned.
//
// Algorithm
//    6. The public suffix is the set of labels from the domain which directly
//       match the labels of the prevailing rule (joined by dots).
//    7. The registered or registrable domain is the public suffix plus one
//       additional label.

// check whether domain is "specific" enough to allow domain cookies
// to be set for this domain.
func allowDomainCookies(domain string) bool {
	// TODO: own algorithm to save unused string gymnastics
	etldp1 := EffectiveTLDPlusOne(domain)
	// fmt.Printf("  etldp1 = %s\n", etldp1)
	return etldp1 != ""
}

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
