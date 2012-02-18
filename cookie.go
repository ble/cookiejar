// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cookiejar

import (
	"strings"
	"time"
	// "fmt"
)

// Cookie is the internal representation of a cookie in our jar.
type Cookie struct {
	Name, Value  string    // name and value of cookie
	Domain, Path string    // domain (no leading .) and path
	Secure       bool      // corresponding fields in http.Cookie
	HttpOnly     bool      // corresponding filed in http.Cookie (unused)
	Expires      time.Time // zero value indicates Session cookie
	HostOnly     bool      // flag for Host vs Domain cookie
	Created      time.Time // used in sorting returned cookies
	LastAccess   time.Time // for internal bookkeeping: keep recently used cookies
}

// Attach method of sort.Interface to []*Cookie
type cookieList []*Cookie

func (cl cookieList) Len() int { return len(cl) }
func (cl cookieList) Less(i, j int) bool {
	in, jn := len(cl[i].Path), len(cl[j].Path)
	if in == jn {
		return cl[i].Created.Before(cl[j].Created)
	}
	return in > jn
}
func (cl cookieList) Swap(i, j int) {
	cl[i], cl[j] = cl[j], cl[i]
}

// shouldSend determines whether to send cookie via a secure request
// to host with path. 
func (c *Cookie) shouldSend(host, path string, secure bool) bool {
	return c.domainMatch(host) &&
		c.pathMatch(path) &&
		!c.isExpired() &&
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

// isExpired checks if cookie c is expired. The zero value of time.Time for
// c.Expires indicates a session cookie (which so not expire until exit).
func (c *Cookie) isExpired() bool {
	return !c.Expires.IsZero() && c.Expires.Before(time.Now())
}
