// Copyright 2012 Volker Dobler. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cookiejar

import (
	"strings"
	"time"
)

// Cookie is the representation of a cookie in the cookie jar.
type Cookie struct {
	Name       string    // the name of the cookie
	Value      string    // the value of cookie
	Domain     string    // the domain (no leading dot)
	Path       string    // the path
	Expires    time.Time // zero value indicates Session cookie
	Secure     bool      // send to https only
	HostOnly   bool      // a Host cookie if true, else a Domain cookie
	HttpOnly   bool      // corresponding field in http.Cookie
	Created    time.Time // time of creation
	LastAccess time.Time // last update or send action
}

// shouldSend determines whether the cookie c qualifies to be included in a
// request to host/path. It is the callers responsibility to check if the
// cookie is expired.
func (c *Cookie) shouldSend(https bool, host, path string) bool {
	return c.domainMatch(host) &&
		c.pathMatch(path) &&
		secureEnough(c.Secure, https)
}

// Every cookie is sent via https.  If the protocol is just http, then the
// cookie must not be marked as secure.
func secureEnough(cookieIsSecure, requestIsSecure bool) bool {
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
	if requestPath == c.Path { // the simple case
		return true
	}

	if strings.HasPrefix(requestPath, c.Path) {
		if c.Path[len(c.Path)-1] == '/' {
			return true // "/any/path" matches "/" and "/any/"
		} else if requestPath[len(c.Path)] == '/' {
			return true // "/any" matches "/any/some"
		}
	}

	return false
}

// Expired checks if the cookie c is expired.
func (c *Cookie) Expired() bool {
	return !c.Session() && c.Expires.Before(time.Now())
}

// Session checks if a cookie c is a session cookie (i.e. has a
// zero value for its Expires field).
func (c *Cookie) Session() bool {
	return c.Expires.IsZero()
}

// ------------------------------------------------------------------------
// Sorting cookies

// sendList is the list of cookies to be sent in a HTTP request.
// sendLists can be sorted according to RFC 6265 section 5.4 point 2.
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
