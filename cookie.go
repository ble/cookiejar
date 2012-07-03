// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cookiejar

import (
	"container/heap"
	"strings"
	"time"
)

// Cookie is the internal representation of a cookie in our jar.
type Cookie struct {
	Name, Value  string    // name and value of cookie
	Domain, Path string    // domain (no leading .) and path
	Expires      time.Time // zero value indicates Session cookie
	Secure       bool      // corresponding fields in http.Cookie
	HostOnly     bool      // flag for Host vs. Domain cookie
	HttpOnly     bool      // corresponding field in http.Cookie
	Created      time.Time // used in sorting returned cookies
	LastAccess   time.Time // for internal bookkeeping: keep recently used cookies
}

// check if cookie Name is set
func (c *Cookie) empty() bool {
	return len(c.Name) == 0
}
func (c *Cookie) clear() {
	c.Name, c.Value = "", ""
}

var (
	// magic value for a clearly expired cookie
	longAgo = time.Date(1, time.March, 2, 4, 5, 6, 0, time.UTC)

	// a point somewhere so far in the future taht we will never reach it
	farFuture = time.Date(9999, time.December, 12, 23, 59, 59, 0, time.UTC)
)

// shouldSend determines whether to send cookie via a secure request
// to host with path. 
func (c *Cookie) shouldSend(host, path string, secure bool, now time.Time) bool {
	// fmt.Printf("shouldSend(%s=%s  to  %s %s %t): %t %t %t %t\n",
	//	c.Name, c.Value, host, path, secure,
	//	c.domainMatch(host), c.pathMatch(path), !c.isExpired(),	secureEnough(c.Secure, secure))
	return c.domainMatch(host) &&
		c.pathMatch(path) &&
		!c.IsExpired(now) &&
		secureEnough(c.Secure, secure)
}

// We send everything via https.  If its just http, the cookie must 
// not be marked as secure.
func secureEnough(cookieIsSecure, requestIsSecure bool) (okay bool) {
	return requestIsSecure || !cookieIsSecure
}

// domainMatch implements "domain-match" of RFC 6265 section 5.1.3:
//   A string domain-matches a given domain string if at least one of the
//   following conditions hold:
//     o  The domain string and the string are identical.  (Note that both
//        the domain string and the string will have been canonicalized to
//        lower case at this point.)
//     o  All of the following conditions hold:
//        *  The domain string is a suffix of the string.
//        *  The last character of the string that is not included in the
//           domain string is a %x2E (".") character.
//        *  The string is a host name (i.e., not an IP address).
func (c *Cookie) domainMatch(host string) bool {
	if c.Domain == host {
		return true
	}
	return !c.HostOnly && strings.HasSuffix(host, "."+c.Domain)
}

// pathMatch implements "path-match" according to RFC 6265 section 5.1.4:
//   A request-path path-matches a given cookie-path if at least one of
//   the following conditions holds:
//     o  The cookie-path and the request-path are identical.
//     o  The cookie-path is a prefix of the request-path, and the last
//        character of the cookie-path is %x2F ("/").
//     o  The cookie-path is a prefix of the request-path, and the first
//        character of the request-path that is not included in the cookie-
//        path is a %x2F ("/") character.
func (c *Cookie) pathMatch(requestPath string) bool {
	// TODO: A better way might be to use strings.LastIndex and reuse 
	// that for both of these conditionals.

	if requestPath == c.Path {
		// the simple case
		return true
	}

	if strings.HasPrefix(requestPath, c.Path) {
		if c.Path[len(c.Path)-1] == '/' {
			//  "/any/path" matches "/" and "/any/"
			return true
		} else if requestPath[len(c.Path)] == '/' {
			//  "/any" matches "/any/some"
			return true
		}
	}

	return false
}

// isExpired checks if cookie c is expired.  The zero value of time.Time for
// c.Expires indicates a session cookie i.e. not expired.
func (c *Cookie) IsExpired(now time.Time) bool {
	return !c.Expires.IsZero() && c.Expires.Before(now)
}

// ------------------------------------------------------------------------
// Sorting of cookies 

// sendList is the list of cookies to be sent in a HTTP request.
type sendList []*Cookie

func (l sendList) Len() int { return len(l) }
func (l sendList) Less(i, j int) bool {
	// RFC 6265 says (section 5.4 point 2) we should sort our cookies
	// like:
	//   o  longer paths go firts
	//   o  for same length paths: earlier creation time goes first
	in, jn := len(l[i].Path), len(l[j].Path)
	if in == jn {
		return l[i].Created.Before(l[j].Created)
	}
	return in > jn
}
func (l sendList) Swap(i, j int) { l[i], l[j] = l[j], l[i] }

// -------------------------------------------------------------------------
// Finding the n least used cookies

// cookieplus is a pointer to a cookie plus additional data
type heapitem struct {
	cookie *Cookie
	data   interface{}
}

type cookieheap []heapitem

func (h cookieheap) Len() int            { return len(h) }
func (h cookieheap) Less(i, j int) bool  { return h[i].cookie.LastAccess.After(h[j].cookie.LastAccess) }
func (h cookieheap) Swap(i, j int)       { h[i], h[j] = h[j], h[i] }
func (h *cookieheap) Push(x interface{}) { *h = append(*h, x.(heapitem)) }
func (h *cookieheap) Pop() interface{} {
	x := (*h)[len(*h)-1]
	*h = (*h)[:len(*h)-1]
	return x
}

// leastUsed keeps the n least used cookies which where insert'ed
// with the additional data in cookies.
type leastUsed struct {
	n    int
	elem cookieheap
}

func newLeastUsed(n int) *leastUsed {
	return &leastUsed{n: n, elem: make(cookieheap, 0, n)}
}

func (lu *leastUsed) insert(cookie *Cookie, data interface{}) {
	heap.Push(&lu.elem, heapitem{cookie, data})
	if len(lu.elem) > lu.n {
		heap.Pop(&lu.elem)
	}
	return
}

func (lu *leastUsed) elements() []heapitem { return lu.elem }
