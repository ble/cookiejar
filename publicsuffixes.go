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
//
// From http://publicsuffix.org/list/:
// A domain is said to match a rule if, when the domain and rule are both
// split,and one compares the labels from the rule to the labels from the
// domain, beginning at the right hand end, one finds that for every pair
// either they are identical, or that the label from the rule is "*" (star).
// The domain may legitimately have labels remaining at the end of this
// matching process.
//
// Algorithm from http://publicsuffix.org/list/
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
// As this algorithm is prohibitive slow we store the list of rules as
// a tree and search this tree for a longest match.  Beeing an exception rule
// is stored naturaly on the node.  Wildcard rules are handled the same
// A rule like "*.a.b" contains a node "a" and this node's kind is wildcard.
// This data structure works as there are no two rules of the type.
// "!a.b" and "*.a.b".
//

import (
	"strings"
)

// Rule is the type or kind of a rule in the public suffix list
type Rule uint8

const (
	None      Rule = iota // not a rule, just internal node
	Normal                // a normal rule like "com.ac"
	Exception             // an exception rule like "!city.kobe.jp"
	Wildcard              // a wildcard rule like "*.ar"
)

// Node describes a single label in public suffix rule.
// The list of rules is stored as a tree of Node nodes.
type Node struct {
	Label string
	Kind  Rule
	Sub   []Node
}

// findLabel looks up the node with label in nodes.
func findLabel(label string, nodes []Node) *Node {
	N := len(nodes)
	if N == 0 {
		return nil
	}

	// Fibonacci search
	// k, M := T[N].k, T[N].M
	k := 0
	for ; fibonacci[k] <= N; k++ {
	}
	k--
	M := fibonacci[k+1] - N - 1
	i, p, q := fibonacci[k]-1, fibonacci[k-1], fibonacci[k-2]

	if label > nodes[i].Label {
		i -= M
		if p == 1 {
			return nil
		}
		i += q
		p -= q
		q -= p
	}

	for {
		if label == nodes[i].Label {
			return &nodes[i]
		}
		if label < nodes[i].Label {
			if q == 0 {
				return nil
			}
			i -= q
			p, q = q, p-q
		} else {
			if p == 1 {
				return nil
			}
			i += q
			p -= q
			q -= p
		}
	}
	panic("not reached")
}

// effectiveTldPlusOne retrieves TLD + 1 respective the publicsuffix + 1.
// For domains which are too short (tld ony, or publixsuffix only)
// the empty string is returned.
//
// Algorithm
//    6. The public suffix is the set of labels from the domain which directly
//       match the labels of the prevailing rule (joined by dots).
//    7. The registered or registrable domain is the public suffix plus one
//       additional label.
func EffectiveTLDPlusOne(domain string) (ret string) {
	parts := strings.Split(domain, ".")
	m := len(parts)
	nodes := PublicSuffixes.Sub
	var np *Node
	for m > 0 {
		m--
		sub := findLabel(parts[m], nodes)
		if sub == nil {
			m++
			break
		}
		nodes = sub.Sub
		np = sub
	}
	// np now points to last matching node

	if np == nil || np.Kind == None {
		// no rule found, default is "*"
		if len(parts) == 2 {
			return domain
		} else if len(parts) > 2 {
			i := len(parts) - 1
			return parts[i-1] + "." + parts[i]
		} else {
			return ""
		}
	}

	switch np.Kind {
	case Normal:
		m--
	case Exception:
	case Wildcard:
		m -= 2
	}
	if m < 0 {
		return ""
	}
	return strings.Join(parts[m:], ".")
}

// check whether domain is "specific" enough to allow domain cookies
// to be set for this domain.
func allowDomainCookies(domain string) bool {
	// TODO: own algorithm to save unused string gymnastics
	etldp1 := EffectiveTLDPlusOne(domain)
	// fmt.Printf("  etldp1 = %s\n", etldp1)
	return etldp1 != ""
}
