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

// JarConfig determines the properties of a CookieJar.
type JarConfig struct {
	// Maximum number of bytes for name + value of each cookie.  Cookies
	// with a higher storage requirement are silently droped while trying
	// to set such a cookie.
	// A value <= 0 indicates "unlimited".
	MaxBytesPerCookie int

	// Maximum number of cookies per logical domain.  The number of cookies
	// for a logical domain contains the cookies for this domain and for 
	// all it's sub-domain as well (thus preventing a malicious domain of 
	// flooding the jar by excessive amounts of cookies from sub-domains.)
	// A value <= 0 indicates "unlimited".
	MaxCookiesPerDomain int

	// Maximum total number of cookies stored in the cookiejar.
	// A value <= 0 indicates "unlimited".
	MaxCookiesTotal int

	// If FlatStorage is set to true, than the internal storage of
	// the cookies will be in a flat array which is faster of only
	// a few cookies from a handful of domains has to be handeled.
	FlatStorage bool

	// RFC 6265 forbides cookies on IP addresses, but browsers typically 
	// do allow host-cookies on an IP address.  This browser-like behaviour
	// can be switched on with AllowHostCookieOnIP
	AllowHostCookieOnIP bool

	// If RejectPublicSuffixes is set to true, than the cookiejar will
	// reject domain cookies on known public suffixes.
	// See http://www.http://publicsuffix.org
	RejectPublicSuffixes bool
}

// MinRFC6265Config contains the minimum values as recommended by RFC 6265.
var MinRFC6265 = JarConfig{
	MaxBytesPerCookie:    4096,
	MaxCookiesPerDomain:  50,
	MaxCookiesTotal:      3000,
	FlatStorage:          false,
	AllowHostCookieOnIP:  false,
	RejectPublicSuffixes: true,
}

// Unlimited describes a jar for arbitary many cookies.
var Unlimited = JarConfig{
	MaxBytesPerCookie:    -1,
	MaxCookiesPerDomain:  -1,
	MaxCookiesTotal:      -1,
	FlatStorage:          false,
	AllowHostCookieOnIP:  true,
	RejectPublicSuffixes: false,
}

// Default describes a small jar, suitable for a controlled (i.e. not
// malicious) environment with some domains and some cookies.
var Default = JarConfig{
	MaxBytesPerCookie:    4096,
	MaxCookiesPerDomain:  -1,
	MaxCookiesTotal:      100,
	FlatStorage:          true,
	AllowHostCookieOnIP:  false,
	RejectPublicSuffixes: true,
}

// -------------------------------------------------------------------------
// Jar

// A Jar implements the http CookieJar interface.
//
// A Jar will neither store cookies in a call to SetCookies nor return 
// cookies from a call to Cookies if the URL is a non-HTTP URL. 
type Jar struct {
	config  JarConfig
	storage Storage

	lock sync.Mutex // the single big lock
	once sync.Once  // used to initialise storage once

	total, empty int
}

// NewJar sets up a cookie jar with the given configuration.
func NewJar(config JarConfig) *Jar {
	if config.MaxBytesPerCookie <= 0 {
		config.MaxBytesPerCookie = 1<<31 - 1 // "unlimited"
	}
	jar := &Jar{
		config: config,
	}
	if config.FlatStorage {
		jar.storage = NewFlatStorage(10, config.MaxCookiesTotal)
	} else {
		fancystore := NewFancyStorage(!config.RejectPublicSuffixes)
		fancystore.maxTotal = config.MaxCookiesTotal
		fancystore.maxPerDomain = config.MaxCookiesPerDomain
		jar.storage = fancystore
	}
	return jar
}

// SetCookies handles the receipt of the cookies in a reply for the given URL.
//
// Cookies with len(Name) + len(Value) > MaxBytesPerCookie (as during creation
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

	maxBytes := jar.config.MaxBytesPerCookie

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

	jar.storage.Cleanup(jar.config.MaxCookiesTotal, jar.config.MaxCookiesPerDomain, now)
}

// GobEncode implements the gob.GobEncoder interface.
// Only nonexpired and persistent cookies will be serialized
// i.e. session cookies (or expired) cookies are discarded
// if gob-encoded and gob-decoded afterwards.
func (jar *Jar) GobEncode() ([]byte, error) {
	return jar.storage.GobEncode()
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
		jar.storage.Delete(domain, path, recieved.Name)
		return deleteCookie
	}

	cookie := jar.storage.Find(domain, path, recieved.Name, now)
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
		if jar.config.AllowHostCookieOnIP && domainAttr == host {
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

	if jar.config.RejectPublicSuffixes {
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
		if !allowCookiesOn(domain) {
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

	cookies := jar.storage.Retrieve(host, path, secure, time.Now())
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
	return jar.storage.All(now)
}
