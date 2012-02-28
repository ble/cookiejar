// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package cookiejar provides a RFC 6265 conforming storage for http cookies.
//
// A Jar will neither store cookies in a call to SetCookies nor return 
// cookies from a call to Cookies if the URL is a non-HTTP URL. 
package cookiejar

import (
	// "bytes"
	// "encoding/gob"
	"fmt"
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
	once    sync.Once
	storage map[string]*flatJar

	total int
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
		return 1<<31 - 1  // MaxInt32
	}
	return val
}

type flatJar struct {
	// not a RWMutex as there is no "read only" access to a cookie as 
	// we have to update LastAccess if we choose to send the cookie
	lock    sync.Mutex  
	cookies []Cookie   // flat list of cookies here
}

// check if no cookies stored here
func (fj *flatJar) empty() bool {
	for _, cookie := range fj.cookies {
		if ! cookie.isExpired() {
			return false
		}
	}
	return true
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
	jar.once.Do(func() { jar.storage = make(map[string]*flatJar) })
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

	_, _, domainKey := publicsuffixRules.info(host)

	fmt.Printf("SetCookies()  host=%s  domainKey=%s  defaultPath=%s\n",
		host, domainKey, defaultpath)
	for _, cookie := range cookies {
		if len(cookie.Name)+len(cookie.Value) > maxBytes {
			continue
		}

		
		action := jar.update(domainKey, nil, host, defaultpath, now, cookie)
		
		fmt.Printf("Action for cookie %s=%s: %d\n", cookie.Name, cookie.Value, action) 

		// make sure every cookie has a distinct creation time
		// which can be used to sort them properly on retrieval.
		// TODO: measure if this is faster than calling time.Now()
		// for each cookie
		now = now.Add(time.Nanosecond)
	}

	jar.cleanup()
}

func (jar *Jar) cleanup() {
	// remove exess (in total) cookies: do expensive counting and removal 
	// only if there might be too many (non-expired) cookies
	total := 0
	expired := 0
	for _, flat := range jar.storage {
		total += len(flat.cookies)
	}
	if total > jar.maxCookiesTotal() {
		expired = jar.expireExessCookies()
		
	}

	// remove all domains without cookies
	for dk := range jar.storage {
		if jar.storage[dk].empty() {
			expired -= len(jar.storage[dk].cookies)
			delete(jar.storage, dk)
		}
	}
}

// set all exess cookies (based on MaxCookiesTotal) to expired
// and report total number of expired cookies
func (jar *Jar) expireExessCookies() (expired int) {
	total := 0
	allowed := jar.maxCookiesTotal()

	// count number of really used (aka non-expired) cookies
	for _, flat := range jar.storage {
		for _, cookie := range flat.cookies {
			if cookie.isExpired() {
				expired++
			} else {
				total++
			} 
		}
		
	}
	exess := total - allowed
	if exess <= 0 {
		return
	}

	toDel := cookieSubset(make([]*Cookie, 0, 3*exess))
	for _, flat := range jar.storage {
	 	for i := range flat.cookies {
			toDel = append(toDel, &flat.cookies[i])
			if len(toDel) >= 3*exess {
				sort.Sort(toDel)
				toDel = toDel[:exess]
			}
		}
	}
	sort.Sort(toDel)
	toDel = toDel[:exess]
	for _, cookie := range toDel {
		cookie.Expires = longAgo
		expired++
	}
	
	return
}

/********
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

**********/

// -------------------------------------------------------------------------
// Internals to SetCookies

// the following action codes are for internal bookkeeping
type updateAction int

const (
	invalidCookie updateAction = iota 
	createCookie
	updateCookie
	deleteCookie
	noSuchCookie  // delete a non-existing Cookie
)

// update is the workhorse which stores, updates or deletes the recieved cookie
// in the jar.  host is the (canonical) hostname from which the cookie was
// recieved and defaultpath the apropriate default path ("directory" of the
// request path. now is the current time.
func (jar *Jar) update(domainKey string, flat *flatJar, host, defaultpath string, now time.Time, recieved *http.Cookie) updateAction {

	// Domain, hostOnly and our storage key
	domain, hostOnly, newDomainKey := jar.domainAndType(host, recieved.Domain)
	if domain == "" {
		return invalidCookie
	}

	if newDomainKey != domainKey {
		// the "completely stupid way to set a host cookie for a
		// public suffix domain" feature of RFC 6265.
		domainKey = newDomainKey
	}
	flat = jar.storage[domainKey]

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
		if flat != nil {
			if d := flat.delete(domain, path, recieved.Name); d {
				return deleteCookie
			}
		}
		return noSuchCookie
	}

	var cookie *Cookie
	if flat == nil {
		// completely new domain
		flat = &flatJar{cookies: make([]Cookie, 1)}
		jar.storage[domainKey] = flat
		fmt.Printf("new flat jar for %s\n", domainKey)
		cookie = &flat.cookies[0]
	} else {
		flat.lock.Lock()
		defer flat.lock.Unlock()
		// look up cookie identified by <domain,path,name>
		cookie = flat.get(domain, path, recieved.Name)
	}

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
func (jar *Jar) domainAndType(host, domainAttr string) (domain string, hostOnly bool, domainKey string) {
	// Host Cookie
	if domainAttr == "" {
		// A RFC6265 conforming Host Cookie: no domain given
		_, _, domainKey = publicsuffixRules.info(host)
		return host, true, domainKey
	}

	if isIP(host) {
		if jar.LaxMode && domainAttr == host {
			// in non-strict mode: allow host cookie if both domain 
			// and host are IP addresses and equal. (IE/FF/Chrome)
			return host, true, host
		}
		// According to RFC 6265 domain-matching includes not beeing 
		// an IP address.
		return "", false, ""
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
		return "", false, ""
	}

	// Never allow Domain Cookies for TLDs
	if i := strings.Index(domain, "."); i == -1 {
		return "", false, ""
	}

	var covered, allowed bool
	covered, allowed, domainKey = publicsuffixRules.info(domain)
	if covered && !allowed {
		// the "domain is a public suffix case"

		if !jar.LaxMode {
			// RFC 6265 section 5.3:
			// 5. If the user agent is configured to reject 
			// "public suffixes" and the domain-attribute is
			// a public suffix:
			//     If the domain-attribute is identical to 
			//     the canonicalized request-host:
			//            Let the domain-attribute be the  
			//            empty string. [a host cookie]
			//        Otherwise:
			//            Ignore the cookie entirely and 
			//            abort these steps.
			if host == domainAttr {
				return host, true, domainKey
			}
			return "", false, ""
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
		return "", false, ""

	}

	// domain must domain-match host:  www.mycompany.com cannot
	// set cookies for .ourcompetitors.com.  
	if host != domain && !strings.HasSuffix(host, "."+domain) {
		return "", false, ""
	}

	return domain, false, domainKey
}

// get lookps up the cookie <domain,path,name> and returns its address
// If no such cookie was found it creates a "new one" with zero value 
// (and returns its address).  "New one" because the storage of an
// expired cookie or the cookie not accessed for the longest time
// might be re-used.
func (jar *flatJar) get(domain, path, name string) *Cookie {
	expiredIdx, oldestIdx := -1, -1
	lastUsed := farFuture
	for index := range jar.cookies {
		// see if the cookie is there
		if domain == jar.cookies[index].Domain &&
			path == jar.cookies[index].Path &&
			name == jar.cookies[index].Name {
			return &jar.cookies[index]
		}

		// track expired and least used ones
		if jar.cookies[index].isExpired() {
			expiredIdx = index
		} else if jar.cookies[index].LastAccess.Before(lastUsed) {
			oldestIdx = index
			lastUsed = jar.cookies[index].LastAccess
		}
	}

	// reuse expired cookie
	if expiredIdx != -1 {
		jar.cookies[expiredIdx].Name = "" // clearn name to indicate "new"
		fmt.Printf("get(%s:%s:%s) expired %d\n", domain,path,name, expiredIdx)
		return &jar.cookies[expiredIdx]
	}

	// reuse least used cookie if domain storage is full
	if len(jar.cookies) >= MaxCookiesPerDomain {
		// reuse least used
		jar.cookies[oldestIdx].Name = "" // clearn name to indicate "new"
		fmt.Printf("get(%s:%s:%s) oldest %d\n", domain,path,name, oldestIdx)
		return &jar.cookies[oldestIdx]
	}

	// a genuine new cookie
	jar.cookies = append(jar.cookies, Cookie{})
	fmt.Printf("get(%s:%s:%s) new %d/%d\n", domain,path,name, len(jar.cookies), cap(jar.cookies))
	return &jar.cookies[len(jar.cookies)-1]
}

// delete the cookie <domain,path,name> in jar. Does nothing if no such 
// cookie is stored.  Returns whether a cookie was deleted or not.
func (jar *flatJar) delete(domain, path, name string) bool {
	for index := 0; index < len(jar.cookies); index++ {
		if domain == jar.cookies[index].Domain &&
			path == jar.cookies[index].Path &&
			name == jar.cookies[index].Name {

			// do not delete, just set to expired long ago
			jar.cookies[index].Expires = longAgo
			return true
		}
	}
	return false
}

/*************************
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
******************************/

// a subset of cookies sortable by
// LastAccess (earlier goes front).
type cookieSubset []*Cookie

func (ss cookieSubset) Len() int           { return len(ss) }
func (ss cookieSubset) Less(i, j int) bool { return ss[i].LastAccess.Before(ss[j].LastAccess) }
func (ss cookieSubset) Swap(i, j int)      { ss[i], ss[j] = ss[j], ss[i] }

// delete all expired cookies from the jar
func (jar *Jar) removeExpiredCookies() {
	/***********
	expiredIdx := make([]int, 0)
	for i := 0; i < len(jar.cookies); i++ {
		if jar.cookies[i].isExpired() {
			expiredIdx = append(expiredIdx, i)
		}
	}
	jar.deleteIdx(expiredIdx)
	*************/
}

// remove cookies if a domain has set more than the allowed number of cookies
// or if the total size exceeds our limit.
func (jar *Jar) removeExcessCookies() {
	/***********************
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
	 *****************************/
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
	_, _, domainKey := publicsuffixRules.info(host)

	flat := jar.storage[domainKey]
	if flat == nil {
		return nil
	}

	flat.lock.Lock()
	defer flat.lock.Unlock()

	// retrieve cookies and sort according to RFC 6265 section 5.2 point 2
	selection := make([]*Cookie, 0)
	for i := range flat.cookies {
		if flat.cookies[i].shouldSend(host, path, secure) {
			selection = append(selection, &flat.cookies[i])
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
