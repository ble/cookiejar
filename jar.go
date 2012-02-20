// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package cookiejar provides a RFC 6265 conforming storage for http cookies.
//
// A Jar will neither store cookies in a call to SetCookies nor return 
// cookies from a call to Cookies if the URL is a non-HTTP URL. 
package cookiejar

import (
	"bytes"
	"encoding/gob"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

// -------------------------------------------------------------------------
// Jar

// A Jar implements the http CookieJar interface.
//
// The MaxCookiesPerDomain and MaxCookiesTotal values may be changed at any 
// time but won't take effect until the next SetCookies or Cleanup call. 
// The MaxbytesperCookie valie may be changed at any time but will affect
// only new cookies stored after the change.
//
// The empty value is a RFC 6265 conforming cookie jar
// which rejects domain cookies for known "public suffixes" (effective top
// level domains such as co.uk whose subdomain are typically not under one 
// administrative control; see http://publicsuffix.org/)
//
// The jar will allow 4096 bytes for len(name)+len(value) of each cookie, 3000 
// cookies in toal and 50 cookies per domain. (These are the minimum numbers 
// required by RFC 6265.
type Jar struct {
	// Maximum number of cookies per logical domain. A vero value indicates
	// 50 cookies per domain
	MaxCookiesPerDomain int

	// maximum total number of cookies in jar
	MaxCookiesTotal int

	// maximum nimber of byte for name + value of each cookie
	MaxBytesPerCookie int

	LaxMode         bool // be a bit more browser like
	AllowAllDomains bool // allow domain cookies also for public suffixes

	lock    sync.Mutex // the BKL of our jar. TODO(vodo) replace by RWMutex
	cookies []Cookie   // flat, unsorted list of current cookies stored

}

// default values if same name field in Jar is zero
const (
	MaxCookiesPerDomain = 50
	MaxCookiesTotal     = 3000
	MaxBytesPerCookie   = 4096
)

// SetCookies handles the receipt of the cookies in a reply for the given URL.
//
// Cookies with len(Name) + len(Value) > maxBytesPerCookie (as during creation
// of the jar) will be ignored silently as well as any cookie with a malformed
// domain field.
func (jar *Jar) SetCookies(u *url.URL, cookies []*http.Cookie) {
	if u == nil || !isHTTP(u) {
		return // this is a strict HTTP only jar
	}

	jar.lock.Lock()
	defer jar.lock.Unlock()

	host, err := host(u)
	if err != nil {
		return
	}
	defaultpath := defaultPath(u)
	now := time.Now()

	maxBytes := jar.MaxBytesPerCookie
	if maxBytes == 0 {
		maxBytes = MaxBytesPerCookie
	}
	for _, cookie := range cookies {
		if len(cookie.Name)+len(cookie.Value) > maxBytes {
			continue
		}

		jar.update(host, defaultpath, now, cookie)

		// make sure every cookie has a distinct creation time
		// which can be used to sort them properly on retrieval.
		// TODO: measure if this is faster than calling time.Now()
		// for each cookie
		now = now.Add(time.Nanosecond)
	}

	jar.removeExpiredCookies()
	jar.removeExcessCookies()
}

// AllCookies returns an "iterator channel" to retrieve all non-expired
// cookies from the jar.
func (jar *Jar) AllCookies() <-chan Cookie {
	ch := make(chan Cookie)
	go func() {
		for _, cookie := range jar.cookies {
			if !cookie.isExpired() {
				ch <- cookie
			}
		}
		close(ch)
	}()
	return ch
}

// GobEncode implements the gob.GobEncoder interface.
// Only nonexpired and persistent cookies will be serialized
// i.e. session cookies (or expired) cookies are discarded
// if gob-encoded and gob-decoded afterwards.
func (jar *Jar) GobEncode() ([]byte, error) {
	data := make([]*Cookie, 0)
	for i := range jar.cookies {
		cookie := &jar.cookies[i]
		if !cookie.Expires.IsZero() && !cookie.isExpired() {
			data = append(data, cookie)
		}
	}
	var buf bytes.Buffer
	encoder := gob.NewEncoder(&buf)
	encoder.Encode(data)
	return buf.Bytes(), nil
}

// GobDecode implements the gob.GobDecoder interface.
// Only nonexpired cookies will be added to the jar.
func (jar *Jar) GobDecode(buf []byte) error {
	data := make([]*Cookie, 0)
	bb := bytes.NewBuffer(buf)
	decoder := gob.NewDecoder(bb)
	err := decoder.Decode(&data)
	if err != nil {
		return err
	}

	jar.cookies = jar.cookies[:0]
	for _, cookie := range data {
		if cookie.isExpired() {
			continue
		}
		jar.cookies = append(jar.cookies, *cookie)
	}
	return nil
}

// -------------------------------------------------------------------------
// Internals to SetCookies

// the following return codes are just used for testing purpose
type updateAction int

const (
	invalidCookie updateAction = iota
	deleteCookie
	createCookie
	updateCookie
)

// update is the workhorse which stores, updates or deletes the recieved cookie
// in the jar.  host is the (canonical) hostname from which the cookie was
// recieved and defaultpath the apropriate default path ("directory" of the
// request path. now is the current time.
func (jar *Jar) update(host, defaultpath string, now time.Time, recieved *http.Cookie) updateAction {
	// Domain (and hostOnly on the fly)
	domain, hostOnly := jar.domainAndType(host, recieved.Domain)
	if domain == "" {
		return invalidCookie
	}

	// Path
	var path string
	if recieved.Path == "" || recieved.Path[0] != '/' {
		path = defaultpath
	} else {
		path = recieved.Path
	}

	// check for deletion of cookie and determine expiration time
	// MaxAge takes precedence over Expires
	var deleteRequest bool
	var expires time.Time
	if recieved.MaxAge < 0 {
		deleteRequest = true
	} else if recieved.MaxAge > 0 {
		expires = now.Add(time.Duration(recieved.MaxAge) * time.Second)
	} else if !recieved.Expires.IsZero() {
		if recieved.Expires.Before(now) {
			deleteRequest = true
		} else {
			expires = recieved.Expires
		}
	}
	if deleteRequest {
		jar.delete(domain, path, recieved.Name)
		return deleteCookie
	}

	// look up cookie identified by <domain,path,name>
	cookie := jar.get(domain, path, recieved.Name)

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

// returns domain and hostOnly flag for a given Set-Cookie header
// with domainAttr as the Domain attribute recieved from host.
// If the given domain/host combination is invalid (i.e. we do
// not allow host to set cookies for domainAttr) an empty domain
// is returned.
func (jar *Jar) domainAndType(host, domainAttr string) (domain string, hostOnly bool) {
	// Host Cookie
	if domainAttr == "" {
		// A RFC6265 conforming Host Cookie: no domain given
		return host, true
	}

	if isIP(host) {
		if jar.LaxMode && domainAttr == host {
			// in non-strict mode: allow host cookie if both domain 
			// and host are IP addresses and equal. (IE/FF/Chrome)
			return host, true
		}
		// According to RFC 6265 domain-matching includes not beeing 
		// an IP address.
		return "", false
	}

	// Else: A Domain Cookie.  We note this fact as hostOnly==false
	// and strip possible leading "."
	domain = domainAttr
	if domain[0] == '.' {
		domain = domain[1:]
	}
	domain = strings.ToLower(domain)

	if len(domain) == 0 || domain[0] == '.' {
		// we recieved either "Domain=." or "Domain=..some.thing"
		// both are illegal
		return "", false
	}

	// Never allow Domain Cookies for TLDs
	if i := strings.Index(domain, "."); i == -1 {
		return "", false
	}

	// Prevent domain cookies for public suffixes / registries
	if !jar.AllowAllDomains {
		covered, allowed, _ := publicsuffixRules.info(domain)
		if covered && !allowed {
			// the "domain is a public suffix case"

			if !jar.LaxMode {
				// RFC 6265 section 5.3:
				// 5. If the user agent is configured to reject 
				// "public suffixes" andthe domain-attribute is
				// a public suffix:
				//     If the domain-attribute is identical to 
				//     the canonicalized request-host:
				//            Let the domain-attribute be the  
				//            empty string. [a host cookie]
				//        Otherwise:
				//            Ignore the cookie entirely and 
				//            abort these steps.
				if host == domainAttr {
					return host, true
				}
				return "", false
			}

			// Strange:  This allows a public suffix domain like 
			// co.uk to set a host cookie by providing a value for 
			// domain in the cookie which is just the opposit of 
			// what everybode else has to do: omit the domain 
			// attribute.
			// Even if this behaviour should not be problematic
			// I cannot see any reason to allow a different way
			// to set a Host Only Cookie for a public suffix or
			// registry as they can (and should) use the normal
			// way and just do not send a domain attribute in the
			// cookie.
			return "", false
		}
	}

	// domain must domain-match host:  www.mycompany.com cannot
	// set cookies for .ourcompetitors.com.  
	if host != domain && !strings.HasSuffix(host, "."+domain) {
		return "", false
	}

	return domain, false
}

// get lookps up the cookie <domain,path,name> and returns its address
// If no such cookie was found it creates a new one with zero value (and
// returns its address)
func (jar *Jar) get(domain, path, name string) *Cookie {
	for index := range jar.cookies {
		if domain == jar.cookies[index].Domain &&
			path == jar.cookies[index].Path &&
			name == jar.cookies[index].Name {
			return &jar.cookies[index]
		}
	}
	jar.cookies = append(jar.cookies, Cookie{})
	return &jar.cookies[len(jar.cookies)-1]
}

// delete the cookie <domain,path,name> in jar. Does nothing if no such 
// cookie is stored.  Returns whether a cookie was deleted or not.
func (jar *Jar) delete(domain, path, name string) bool {
	for index := 0; index < len(jar.cookies); index++ {
		if domain == jar.cookies[index].Domain &&
			path == jar.cookies[index].Path &&
			name == jar.cookies[index].Name {
			// delete cookie at index i by replacing with last in 
			// jar.cookies and truncating
			n := len(jar.cookies) - 1
			if index != n {
				jar.cookies[index] = jar.cookies[n]
			}
			jar.cookies = jar.cookies[:n]
			return true
		}
	}
	return false
}

// delete cookie at indices in jar.cookies by replacing with last (undeleted) cookies
func (jar *Jar) deleteIdx(indices []int) {
	for _, i := range indices {
		if i >= len(jar.cookies) {
			break
		}

		// find last non-deleted cookie
		e := len(jar.cookies) - 1
		for ; e > i; e-- {
			okay := true
			for _, j := range indices {
				if e == j {
					okay = false
					break
				}
			}
			if okay {
				break
			}
		}
		if e == i {
			// all from i to end expired
			jar.cookies = jar.cookies[:i]
			break
		} else {
			// copy last non-expired (e) to pos index and strip
			jar.cookies[i] = jar.cookies[e]
			jar.cookies = jar.cookies[:e]
		}
	}
}

// a subset of cookies in a jar identified by their index, sortable by
// LastAccess (earlier goes front).
type cookieSubset struct {
	jar *Jar  // which jar
	idx []int // which indices in jar.cookies
}

func (ss cookieSubset) Len() int { return len(ss.idx) }
func (ss cookieSubset) Less(i, j int) bool {
	return ss.jar.cookies[ss.idx[i]].LastAccess.Before(ss.jar.cookies[ss.idx[j]].LastAccess)
}
func (ss cookieSubset) Swap(i, j int) { ss.idx[i], ss.idx[j] = ss.idx[j], ss.idx[i] }

// delete all expired cookies from the jar
func (jar *Jar) removeExpiredCookies() {
	expiredIdx := make([]int, 0)
	for i := 0; i < len(jar.cookies); i++ {
		if jar.cookies[i].isExpired() {
			expiredIdx = append(expiredIdx, i)
		}
	}
	jar.deleteIdx(expiredIdx)
}

// remove cookies if a domain has set more than the allowed number of cookies
// or if the total size exceeds our limit.
func (jar *Jar) removeExcessCookies() {
	// pass 1: excessive use of one domain
	cookiesForDomain := make(map[string][]int)
	for i := range jar.cookies {
		domain := jar.cookies[i].Domain
		if list, ok := cookiesForDomain[domain]; !ok {
			cookiesForDomain[domain] = []int{i}
		} else {
			cookiesForDomain[domain] = append(list, i)
		}
	}
	maxPerDomain := jar.MaxCookiesPerDomain
	if maxPerDomain == 0 {
		maxPerDomain = MaxCookiesPerDomain
	}
	for _, ci := range cookiesForDomain {
		if len(ci) <= maxPerDomain {
			continue
		}
		// sort by LastAccess and remove seldomly used excess cookies
		ss := cookieSubset{jar, ci}
		sort.Sort(ss)
		jar.deleteIdx(ss.idx[:len(ci)-maxPerDomain])
	}

	// pass 2: limit total count
	maxTotal := jar.MaxCookiesTotal
	if maxTotal == 0 {
		maxTotal = MaxCookiesTotal
	}
	if len(jar.cookies) > maxTotal {
		allIdx := make([]int, len(jar.cookies))
		for i := range jar.cookies {
			allIdx[i] = i
		}
		ss := cookieSubset{jar, allIdx}
		sort.Sort(ss)
		jar.deleteIdx(ss.idx[:len(jar.cookies)-maxTotal])
	}
}

// -------------------------------------------------------------------------
// Retrieve Cookies

// SetCookies handles the receipt of the cookies in a reply for the given URL.
func (jar *Jar) Cookies(u *url.URL) []*http.Cookie {
	if !isHTTP(u) {
		return nil // this is a strict HTTP only jar
	}

	jar.lock.Lock()
	defer jar.lock.Unlock()

	// set up host, path and secure
	host, err := host(u)
	if err != nil {
		return nil
	}
	secure := isSecure(u)
	path := u.Path
	if path == "" {
		path = "/"
	}

	// retrieve cookies and sort according to RFC 6265 section 5.2 point 2
	selection := make([]*Cookie, 0)
	for i := range jar.cookies {
		if jar.cookies[i].shouldSend(host, path, secure) {
			selection = append(selection, &jar.cookies[i])
		}
	}
	sort.Sort(cookieList(selection))

	// fill into slice of http.Cookies
	now := time.Now()
	cookies := make([]*http.Cookie, len(selection))
	for i := range selection {
		cookies[i] = &http.Cookie{Name: selection[i].Name, Value: selection[i].Value}

		// update last access with a strictly increasing timestamp
		selection[i].LastAccess = now
		now = now.Add(time.Nanosecond)
	}

	return cookies
}
