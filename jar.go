// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package cookiejar provides a RFC 6265 conforming storage for http cookies.
//
// The Jar implementation of the http.CookeiJar interface is a general purpose
// implementation which may be used to store and retireve cookies from 
// arbitary sites.
// 
//
package cookiejar

import (
	// "bytes"
	// "encoding/gob"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

var _ = fmt.Println

// default values if same name field in Jar is zero
const (
	MaxCookiesPerDomain = 50
	MaxCookiesTotal     = 3000
	MaxBytesPerCookie   = 4096
)

// -------------------------------------------------------------------------
// Jar

// A Jar implements the http CookieJar interface.
//
// The empty value of Jar is a RFC 6265 conforming cookie jar which rejects 
// domain cookies for known "public suffixes" (effective top level domains 
// such as co.uk whose subdomain are typically not under one administrative 
// control; see http://publicsuffix.org/).  The jar will allow 4096 bytes 
// for len(name)+len(value) of each cookie, 3000 cookies in toal and  
// 50 cookies per domain which are the minimum numbers required by RFC 6265.
//
// A Jar will neither store cookies in a call to SetCookies nor return 
// cookies from a call to Cookies if the URL is a non-HTTP URL. 
// 
// Changing MaxCookiesPerDomain and MaxCookiesTotal won't take effect until 
// the next invocation of SetCookies.  Changing MaxbytesperCookie, LaxMode 
// and AllowAllDomains will affect only new cookies stored after the change. 
// Changing these values is not safe while other goroutines set or retrieve
// cookies.
//
type Jar struct {
	// Maximum number of cookies per logical domain.  The number of cookies
	// for a logical domain contains the cookies for this domain and for 
	// all it's sub-domain as well (thus preventing a malicious domain of 
	// flooding the jar by excessive amounts of cookies from sub-domains.)
	// A value < 0 indicates "unlimited".
	MaxCookiesPerDomain int

	// Maximum total number of cookies in jar.
	// A value < 0 indicates "unlimited".
	MaxCookiesTotal int

	// Maximum number of bytes for name + value of each cookie.  Cookies
	// with a higher storage requirement are silently droped while trying
	// to set such a cookie.
	// A value < 0 indicates "unlimited".
	MaxBytesPerCookie int

	// If LaxMode is true, than the jar will be a bit more browser like and
	// allow a host cookie for an IP address.
	LaxMode bool

	// If true then domain cookies may be set for a public suffix domain
	// too.
	AllowAllDomains bool

	lock    sync.Mutex // the single big lock
	once    sync.Once  // used to initialise storage once
	Storage Storage

	total int // allocate space in total = \sum_{f\in storage} len(f.cookies)
	empty int // known entries in total to be empty i.e. expired or delted
}

func (jar *Jar) maxCookiesTotal() int {
	return defaultVal(jar.MaxCookiesTotal, MaxCookiesTotal)
}
func (jar *Jar) maxCookiesPerDomain() int {
	return defaultVal(jar.MaxCookiesPerDomain, MaxCookiesPerDomain)
}
func (jar *Jar) maxBytesPerCookie() int {
	return defaultVal(jar.MaxBytesPerCookie, MaxBytesPerCookie)
}
func defaultVal(val, dflt int) int {
	if val == 0 {
		return dflt
	} else if val < 0 {
		return 1<<31 - 1 // MaxInt32
	}
	return val
}

// SetCookies handles the receipt of the cookies in a reply for the given URL.
//
// Cookies with len(Name) + len(Value) > maxBytesPerCookie (as during creation
// of the jar) will be ignored silently as well as any cookie with a malformed
// domain field.
func (jar *Jar) SetCookies(u *url.URL, cookies []*http.Cookie) {
	if u == nil || !isHTTP(u) {
		return // this is a strict HTTP only jar
	}

	host, err := host(u)
	if err != nil {
		return
	}
	defaultpath := defaultPath(u)
	now := time.Now()

	maxBytes := jar.maxBytesPerCookie()

	jar.lock.Lock()
	defer jar.lock.Unlock()

	for _, cookie := range cookies {
		if len(cookie.Name)+len(cookie.Value) > maxBytes {
			continue
		}

		action := jar.update(host, defaultpath, now, cookie)

		switch action {
		case createCookie:
			jar.total++
		case updateCookie, invalidCookie:
			// nothing
		case deleteCookie:
			jar.empty++
		default:
			panic("Ooops")
		}
		// fmt.Printf("Action for cookie %s=%s: %d\n", cookie.Name, cookie.Value, action) 

		// make sure every cookie has a distinct creation time
		// which can be used to sort them properly on retrieval.
		// TODO: measure if this is faster than calling time.Now()
		// for each cookie
		now = now.Add(time.Nanosecond)
	}

	jar.Storage.Cleanup(jar.MaxCookiesTotal, jar.MaxCookiesPerDomain, now)
}

// GobEncode implements the gob.GobEncoder interface.
// Only nonexpired and persistent cookies will be serialized
// i.e. session cookies (or expired) cookies are discarded
// if gob-encoded and gob-decoded afterwards.
func (jar *Jar) GobEncode() ([]byte, error) {
	return jar.Storage.GobEncode()
}

// GobDecode implements the gob.GobDecoder interface.
// Only nonexpired cookies will be added to the jar.
func (jar *Jar) GobDecode(buf []byte) error {
	/***
	bb := bytes.NewBuffer(buf)
	decoder := gob.NewDecoder(bb)
	err := decoder.Decode()
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
	 **********/
	return nil
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

// update is the workhorse which stores, updates or deletes the recieved cookie
// in the jar.  host is the (canonical) hostname from which the cookie was
// recieved and defaultpath the apropriate default path ("directory" of the
// request path. now is the current time.
func (jar *Jar) update(host, defaultpath string, now time.Time, recieved *http.Cookie) updateAction {

	// Domain, hostOnly and our storage key
	domain, hostOnly, err := jar.domainAndType(host, recieved.Domain)
	if err != nil {
		return invalidCookie
	}

	// Path
	path := recieved.Path
	if path == "" || path[0] != '/' {
		path = defaultpath
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
		jar.Storage.Delete(domain, path, recieved.Name)
		return deleteCookie
	}

	cookie := jar.Storage.Find(domain, path, recieved.Name, now)
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
	ErrNoHostname      = errors.New("No hostname (IP only) available")
	ErrMalformedDomain = errors.New("Domain attribute of cookie is malformed")
	ErrTLDDomainCookie = errors.New("No domain cookies for TLDs allowed")
	ErrIllegalPSDomain = errors.New("Illegal cookie domain attribute for public suffix")
	ErrBadDomain       = errors.New("Bad cookie domaine attribute")
)

// domainAndType determines the Cookies Domain and HostOnly attribute
// from the host from which the cookie with the domainAttribute was
// recieved.
func (jar *Jar) domainAndType(host, domainAttr string) (domain string, hostOnly bool, err error) {
	if domainAttr == "" {
		// A RFC6265 conforming Host Cookie: no domain given
		return host, true, nil
	}

	// no hostname, but just an IP address
	if isIP(host) {
		if jar.LaxMode && domainAttr == host {
			// in non-strict mode: allow host cookie if both domain 
			// and host are IP addresses and equal. (IE/FF/Chrome)
			return host, true, nil
		}
		// According to RFC 6265 domain-matching includes not beeing 
		// an IP address.
		return "", false, ErrNoHostname
	}

	// If valid: A Domain Cookie (with one strange exeption).
	// We note the fact "domain cookie" as hostOnly==false and strip 
	// possible leading "." from the domain.
	domain = domainAttr
	if domain[0] == '.' {
		domain = domain[1:]
	}
	domain = strings.ToLower(domain)
	if len(domain) == 0 || domain[0] == '.' {
		// we recieved either "Domain=." or "Domain=..some.thing"
		// both are illegal
		return "", false, ErrMalformedDomain
	}

	// Never allow Domain Cookies for TLDs.  TODO: decide on "localhost".
	if i := strings.Index(domain, "."); i == -1 {
		return "", false, ErrTLDDomainCookie
	}

	if !jar.AllowAllDomains {
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
		covered, allowed, _ := publicsuffixRules.info(domain)
		if covered && !allowed {
			// the "domain is a public suffix" case
			if host == domainAttr {
				return host, true, nil
			}
			return "", false, ErrIllegalPSDomain
		}
	}

	// domain must domain-match host:  www.mycompany.com cannot
	// set cookies for .ourcompetitors.com.  
	if host != domain && !strings.HasSuffix(host, "."+domain) {
		return "", false, ErrBadDomain
	}

	return domain, false, nil
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

	cookies := jar.Storage.Retrieve(host, path, secure, time.Now())
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

func (jar *Jar) All(now time.Time) []*Cookie {
	return jar.Storage.All(now)
}
