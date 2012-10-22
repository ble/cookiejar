// Copyright 2012 Volker Dobler. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package cookiejar provides a in-memory storage for http cookies.
//
// Jar implements the http.CookieJar interface and conforms
// to RFC 6265 with the one exception: Cookies from internationalized
// domain names are not handled properly.
//
package cookiejar

// BUG
// Jar does not handle internationalized domain names (IDN).
// The Jar should (but does not) transform the domain name of the URL
// to punycode before matching the domain attribute of a recieved cookie.

import (
	"errors"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

// -------------------------------------------------------------------------
// Jar

// A Jar implements the http.CookieJar interface.
//
// Jar keeps all cookies in memory and does not limit the amount of stored
// cookies.
// Jar will neither store cookies in a call to SetCookies nor return cookies
// from a call to Cookies if the URL is a non-HTTP URL.
// As HTTP would require full qualified domain names in the URL anyway, this
// cookie jar implementation treats all domain names as beeing fully qualified
// (absolute) even if not ending in a ".".
type Jar struct {
	// MaxBytesPerCookie is the maximum number of bytes allowed for name plus
	// value of the cookie.  Cookies whith len(Name)+len(Value) exceeding
	// MaxBytesPerCookie are not stored.
	// A value <= 0 indicates unlimited storage capacity.
	MaxBytesPerCookie int

	// HostCookiesOnIP may be set to true to allow a host cookie
	// on an IP address.  Host cookies on an IP address are forbidden
	// by RCF 6265 but most browsers do allow them.
	HostCookieOnIP bool

	// DomainCookiesOnPublicSuffixes may be set to true to allow domain cookies
	// on all domains, especially on top level domains and domains
	// browsers normaly deny domain cookies like co.uk.
	// See http://publicsuffix.org/ for detailed information.
	DomainCookiesOnPublicSuffixes bool

	content storage // our cookies

	sync.Mutex
}

// NewJar sets up an empty cookie jar.
// A Jar with boxedStorage can handle cookies from lots of different
// domains more efficient than a Jar with flat storage.
//
// The created Jar will allow 4096 bytes for Name plus Value, won't accpet
// host cookies for IP-addresses and won't accept a domain cookie for a
// known public suffix domain.
func NewJar(boxedStorage bool) *Jar {
	jar := Jar{
		MaxBytesPerCookie:             4096,
		HostCookieOnIP:                false,
		DomainCookiesOnPublicSuffixes: false,
	}
	if boxedStorage {
		tmp := make(boxed)
		jar.content = &tmp
	} else {
		tmp := make(flat, 0, 16)
		jar.content = &tmp
	}

	return &jar
}

// -------------------------------------------------------------------------
// The methods of the http.CookieJar interface.

// SetCookies updates the content of jar with the cookies recieved
// from a request to u.
//
// Cookies with len(Name) + len(Value) > MaxBytesPerCookie will be ignored
// silently as well as any cookie with a malformed domain field.
func (jar *Jar) SetCookies(u *url.URL, cookies []*http.Cookie) {
	if u == nil || !isHTTP(u) {
		return // this is a strict HTTP only jar
	}

	host, err := host(u)
	if err != nil {
		return
	}
	defaultpath := defaultPath(u)

	jar.Lock()
	defer jar.Unlock()

	for _, cookie := range cookies {
		if jar.MaxBytesPerCookie > 0 && len(cookie.Name)+len(cookie.Value) > jar.MaxBytesPerCookie {
			continue
		}
		jar.update(host, defaultpath, cookie)
	}
}

// SetCookies handles the receipt of the cookies in a reply for the given URL.
func (jar *Jar) Cookies(u *url.URL) []*http.Cookie {
	if !isHTTP(u) {
		return nil // this is a strict HTTP only jar
	}

	jar.Lock()
	defer jar.Unlock()

	// set up host, path and secure
	host, err := host(u)
	if err != nil {
		return nil
	}

	https := isSecure(u)
	path := u.Path
	if path == "" {
		path = "/"
	}

	cookies := jar.content.retrieve(https, host, path)
	sort.Sort(sendList(cookies))

	// fill into slice of http.Cookies and update LastAccess time
	now := time.Now()
	httpCookies := make([]*http.Cookie, len(cookies))
	for i, cookie := range cookies {
		httpCookies[i] = &http.Cookie{Name: cookie.Name, Value: cookie.Value}

		// update last access with a strictly increasing timestamp
		cookie.LastAccess = now
		now = now.Add(time.Nanosecond)
	}

	return httpCookies
}

// -------------------------------------------------------------------------
// Other exported methods

// All returns a copy of all non-expired cookies in the jar.
func (jar *Jar) All() []Cookie {
	if b, ok := jar.content.(*boxed); ok {
		cookies := make([]Cookie, 0, 32)
		for _, f := range *b {
			for _, cookie := range *f {
				if cookie.Expired() {
					continue
				}
				cookies = append(cookies, *cookie)
			}
		}
		return cookies
	} else {
		f := jar.content.(*flat)
		cookies := make([]Cookie, 0, len(*f))
		for _, cookie := range *f {
			if cookie.Expired() {
				continue
			}
			cookies = append(cookies, *cookie)
		}
		return cookies
	}
	panic("Not reached")
}

// Add adds all non-expired elements of cookies to the jar.  Expired cookies
// are silently ignored.  If a cookie is already present in the jar it will
// be overwritten.  The LastAccess field of the given cookies are not modified.
func (jar *Jar) Add(cookies []Cookie) {
	for _, cookie := range cookies {
		if cookie.Expired() {
			continue
		}
		c := jar.content.find(cookie.Domain, cookie.Path, cookie.Name)
		*c = cookie
	}
}

// Remove deletes the cookie identified by domain, path and name from jar.
// The function returns true if the cookie was present in the jar.
func (jar *Jar) Remove(domain, path, name string) bool {
	// sanitize domain
	domain = strings.Trim(strings.ToLower(domain), ".")
	existed := jar.content.delete(domain, path, name)
	return existed
}

// -------------------------------------------------------------------------
// Internals to SetCookies

// the following action codes are for internal bookkeeping
type updateAction int

const (
	invalidCookie updateAction = iota
	createCookie
	updateCookie
	deleteCookie
	noSuchCookie
)

// host returns the (canonical) host from an URL u.
// See RFC 6265 section 5.1.2
// TODO: idns are not handeled at all.
func host(u *url.URL) (host string, err error) {
	host = strings.ToLower(u.Host)
	if strings.HasSuffix(host, ".") {
		// treat all domain names the same:
		// strip trailing dot from fully qualified domain names
		host = host[:len(host)-1]
	}
	if strings.Index(host, ":") != -1 {
		host, _, err = net.SplitHostPort(host)
		if err != nil {
			return "", err
		}
	}

	host, err = punycodeToASCII(host)
	if err != nil {
		return "", err
	}

	return host, nil
}

// isSecure checks for https scheme in u.
func isSecure(u *url.URL) bool {
	return strings.ToLower(u.Scheme) == "https"
}

// isHTTP checks for http or https scheme in u.
func isHTTP(u *url.URL) bool {
	scheme := strings.ToLower(u.Scheme)
	return scheme == "http" || scheme == "https"
}

// isIP check if host is formaly an IPv4 address.
func isIP(host string) bool {
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return ip.String() == host
}

// This is a dummy helper function which once can do the IDN stuff.
func punycodeToASCII(s string) (string, error) {
	return s, nil
}

// defaultPath returns "directory" part of path from u. Empty and
// malformed paths yield "/".
// See RFC 6265 section 5.1.4:
//    path in url  |  directory
//   --------------+------------
//    ""           |  "/"
//    "xy/z"       |  "/"
//    "/abc"       |  "/"
//    "/ab/xy/km"  |  "/ab/xy"
//    "/abc/"      |  "/abc"
// A trailing "/" is removed during storage to faciliate the test in
// pathMatch().
func defaultPath(u *url.URL) string {
	path := u.Path

	// the "" and "xy/z" case
	if len(path) == 0 || path[0] != '/' {
		return "/"
	}

	// path starts with "/" --> i!=-1
	i := strings.LastIndex(path, "/")
	if i == 0 {
		// the "/abc" case
		return "/"
	}

	// the "/ab/xy/km" and "/abc/" case
	return path[:i]
}

// update is the workhorse which stores, updates or deletes the recieved cookie
// in the jar.  host is the (canonical) hostname from which the cookie was
// recieved and defaultpath the apropriate default path ("directory" of the
// request path.
func (jar *Jar) update(host, defaultpath string, recieved *http.Cookie) updateAction {

	// Domain, hostOnly and our storage key
	domain, hostOnly, err := jar.domainAndType(host, recieved.Domain)
	if err != nil {
		return invalidCookie
	}

	now := time.Now()

	// Path
	path := recieved.Path
	if path == "" || path[0] != '/' {
		path = defaultpath
	}

	// Check for deletion of cookie and determine expiration time:
	// MaxAge takes precedence over Expires.
	var deleteRequest bool
	var expires time.Time
	if recieved.MaxAge < 0 {
		deleteRequest = true
	} else if recieved.MaxAge > 0 {
		expires = time.Now().Add(time.Duration(recieved.MaxAge) * time.Second)
	} else if !recieved.Expires.IsZero() {
		if recieved.Expires.Before(now) {
			deleteRequest = true
		} else {
			expires = recieved.Expires
		}
	}
	if deleteRequest {
		if existed := jar.content.delete(domain, path, recieved.Name); existed {
			return deleteCookie
		} else {
			return noSuchCookie
		}
	}

	cookie := jar.content.find(domain, path, recieved.Name)
	if len(cookie.Name) == 0 {
		// a new cookie
		cookie.Domain = domain
		cookie.HostOnly = hostOnly
		cookie.Path = path
		cookie.Name = recieved.Name
		cookie.Value = recieved.Value
		cookie.HttpOnly = recieved.HttpOnly
		cookie.Secure = recieved.Secure
		cookie.Expires = expires
		cookie.Created = now
		cookie.LastAccess = now
		return createCookie
	}

	// an update for a cookie
	cookie.HostOnly = hostOnly
	cookie.Value = recieved.Value
	cookie.HttpOnly = recieved.HttpOnly
	cookie.Expires = expires
	cookie.Secure = recieved.Secure
	cookie.LastAccess = now
	return updateCookie
}

var (
	errNoHostname      = errors.New("No hostname (IP only) available")
	errMalformedDomain = errors.New("Domain attribute of cookie is malformed")
	errTLDDomainCookie = errors.New("No domain cookies for TLDs allowed")
	errIllegalPSDomain = errors.New("Illegal cookie domain attribute for public suffix")
	errBadDomain       = errors.New("Bad cookie domaine attribute")
)

// domainAndType determines the Cookies Domain and HostOnly attribute.
// It uses the host name the cookie was recieved from and the domain attribute
// of the cookie.
func (jar *Jar) domainAndType(host, domainAttr string) (domain string, hostOnly bool, err error) {
	if domainAttr == "" {
		// A RFC6265 conforming Host Cookie: no domain given
		return host, true, nil
	}

	// no hostname, but just an IP address
	if isIP(host) {
		if jar.HostCookieOnIP && domainAttr == host {
			// in non-strict mode: allow host cookie if both domain
			// and host are IP addresses and equal. (IE/FF/Chrome)
			return host, true, nil
		}
		// According to RFC 6265 domain-matching includes not beeing
		// an IP address.
		return "", false, errNoHostname
	}

	// If valid: A Domain Cookie (with one strange exeption).
	// We note the fact "domain cookie" as hostOnly==false and strip
	// possible leading "." from the domain.
	domain = domainAttr
	if domain[0] == '.' {
		domain = domain[1:]
	}

	if len(domain) == 0 || domain[0] == '.' {
		// we recieved either "Domain=." or "Domain=..some.thing"
		// both are illegal
		return "", false, errMalformedDomain
	}
	domain = strings.ToLower(domain) // see RFC 6265 section 5.2.3

	if domain[len(domain)-1] == '.' {
		// we recieved stuff like "Domain=www.example.com."
		// Browsers do handle such stuff (actually differently) but
		// RFC 6265 seems to be clear here (e.g. section 4.1.2.3) in
		// requiering a reject.  4.1.2.3 is not normative, but
		// "Domain Matching" (5.1.3) and "Canonicalized Host Names"
		// (5.1.2) are.
		return "", false, errMalformedDomain
	}

	// Never allow Domain Cookies for TLDs.  TODO: decide on "localhost".
	if i := strings.Index(domain, "."); i == -1 {
		return "", false, errTLDDomainCookie
	}

	if !jar.DomainCookiesOnPublicSuffixes {
		// RFC 6265 section 5.3:
		// 5. If the user agent is configured to reject "public
		// suffixes" and the domain-attribute is a public suffix:
		//     If the domain-attribute is identical to the
		//     canonicalized request-host:
		//            Let the domain-attribute be the empty string.
		//            [that is a host cookie]
		//        Otherwise:
		//            Ignore the cookie entirely and abort these
		//            steps.  [error]
		// fmt.Printf("  allowDomainCookies(%s) = %t\n", domain, allowDomainCookies(domain))

		if !allowDomainCookies(domain) {
			// the "domain is a public suffix" case
			if host == domainAttr {
				return host, true, nil
			}
			return "", false, errIllegalPSDomain
		}
	}

	// domain must domain-match host:  www.mycompany.com cannot
	// set cookies for .ourcompetitors.com.
	if host != domain && !strings.HasSuffix(host, "."+domain) {
		return "", false, errBadDomain
	}

	return domain, false, nil
}
