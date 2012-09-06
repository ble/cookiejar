// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cookiejar

import (
	"fmt"
	"net/http"
	"net/url"
	"testing"
)

var exampleUrl, updateUrl *url.URL
var exampleCookies []*http.Cookie

func init() {
	exampleUrl, _ = url.Parse("http://www.example.org/some/path")
	updateUrl, _ = url.Parse("http://www.update.org/")
	exampleCookies = []*http.Cookie{
		&http.Cookie{Name: "theCookieName1", Value: "some longer cookie Value"},
		&http.Cookie{Name: "theCookieName2", Value: "some longer cookie Value", MaxAge: 600},
		&http.Cookie{Name: "theCookieName3", Value: "some longer cookie Value", Path: "/some/path/deep"},
	}
}

// assuming a (3000 cookie / 50 per domain)-jar fill 60*fd domains with 50*fc random cookies
// and 
func fillJar(jar *Jar, fd, fc float64) {
	dn := int(12*fd + 0.5)
	cn := int(50*fc + 0.5)
	dnames := []string{"foo", "bar", "baz", "qux", "hello", "anything", "company"}
	rd := 0
	cookies := make([]http.Cookie, cn)
	pcookies := make([]*http.Cookie, cn)
	for p := range pcookies {
		pcookies[p] = &cookies[p]
	}
	for _, tld := range []string{"com", "net", "info", "biz", "org"} {
		for i := 0; i < dn; i++ {
			for j := range cookies {
				cookies[j].Name = fmt.Sprintf("%c%c%c", 'a'+(j%26), 'A'+(j%20), 'z'-(j%7))
				cookies[j].Value = "all the same value"
				// fmt.Printf("%d Cookie %s for %s\n", j, cookies[j].Name, domain)
			}
			dc := 'o' + i
			u, _ := url.Parse(fmt.Sprintf("http://www.%c%c-%s.%s", dc, dc, dnames[rd], tld))
			rd = (rd + 1) % len(dnames)
			jar.SetCookies(u, pcookies)
		}
	}
}

// -------------------------------------------------------------------------
// Inserting three completely new (new domain, new cookie) cookies

var cfgFlat = JarConfig{
	MaxBytesPerCookie:    -1,
	MaxCookiesPerDomain:  -1,
	MaxCookiesTotal:      -1,
	FlatStorage:          true,
	AllowHostCookieOnIP:  true,
	RejectPublicSuffixes: false,
}
var cfgFancy = JarConfig{
	MaxBytesPerCookie:    -1,
	MaxCookiesPerDomain:  -1,
	MaxCookiesTotal:      -1,
	FlatStorage:          false,
	AllowHostCookieOnIP:  true,
	RejectPublicSuffixes: false,
}

// insert into completely empty jar
func BenchmarkInsertFreshFlatJar(b *testing.B) {
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		jar := NewJar(cfgFlat)
		b.StartTimer()
		jar.SetCookies(exampleUrl, exampleCookies)
	}
}
func BenchmarkInsertFreshFancyJar(b *testing.B) {
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		jar := NewJar(cfgFancy)
		b.StartTimer()
		jar.SetCookies(exampleUrl, exampleCookies)
	}
}

// insert into jar which has allready a cookie for that domain
func BenchmarkInsertSetFlatJar(b *testing.B) {
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		jar := NewJar(cfgFlat)
		jar.SetCookies(exampleUrl, []*http.Cookie{
			&http.Cookie{Name: "hereAlready", Value: "someValue"}})
		b.StartTimer()
		jar.SetCookies(exampleUrl, exampleCookies)
	}
}
func BenchmarkInsertSetFancyJar(b *testing.B) {
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		jar := NewJar(cfgFancy)
		jar.SetCookies(exampleUrl, []*http.Cookie{
			&http.Cookie{Name: "hereAlready", Value: "someValue"}})
		b.StartTimer()
		jar.SetCookies(exampleUrl, exampleCookies)
	}
}

// insert into half full jar
func BenchmarkInsertHalfFlatJar(b *testing.B) {
	jar := NewJar(cfgFlat)
	fillJar(jar, 0.75, 0.75)
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		theRuleCache = ruleCache{cache: make([]cacheEntry, 20)}
		u, _ := url.Parse(fmt.Sprintf("http://www.%dexample.org/some/path", i))
		b.StartTimer()
		jar.SetCookies(u, exampleCookies)
	}
}
func BenchmarkInsertHalfFancyJar(b *testing.B) {
	jar := NewJar(cfgFancy)
	fillJar(jar, 0.75, 0.75)
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		theRuleCache = ruleCache{cache: make([]cacheEntry, 20)}
		u, _ := url.Parse(fmt.Sprintf("http://www.%dexample.org/some/path", i))
		b.StartTimer()
		jar.SetCookies(u, exampleCookies)
	}
}

// insert into completely full jar, thus deletion of exxess cookies
func BenchmarkInsertFullFlatJar(b *testing.B) {
	jar := NewJar(cfgFlat)
	fillJar(jar, 1, 1)
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		theRuleCache = ruleCache{cache: make([]cacheEntry, 20)}
		u, _ := url.Parse(fmt.Sprintf("http://www.%dexample.org/some/path", i))
		b.StartTimer()
		jar.SetCookies(u, exampleCookies)
	}
}
func BenchmarkInsertFullFancyJar(b *testing.B) {
	jar := NewJar(cfgFancy)
	fillJar(jar, 1, 1)
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		theRuleCache = ruleCache{cache: make([]cacheEntry, 20)}
		u, _ := url.Parse(fmt.Sprintf("http://www.%dexample.org/some/path", i))
		b.StartTimer()
		jar.SetCookies(u, exampleCookies)
	}
}

// -------------------------------------------------------------------------
// Getting existing cookie from jar

// from jar containing just this cookie
func BenchmarkGetExSetJar(b *testing.B) {
	b.StopTimer()
	jar := &Jar{}
	jar.SetCookies(exampleUrl, exampleCookies)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		jar.Cookies(exampleUrl)
	}
}

// from half full jar
func BenchmarkGetExHalfJar(b *testing.B) {
	b.StopTimer()
	jar := &Jar{}
	fillJar(jar, 0.75, 0.75)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		jar.Cookies(exampleUrl)
	}
}

// from completely full jar
func BenchmarkGetExFullJar(b *testing.B) {
	b.StopTimer()
	jar := &Jar{}
	fillJar(jar, 1, 1)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		jar.Cookies(exampleUrl)
	}
}

// -------------------------------------------------------------------------
// Getting Non-existing cookie from jar

// from jar containing just this cookie
func BenchmarkGetNexSetJar(b *testing.B) {
	b.StopTimer()
	jar := &Jar{}
	jar.SetCookies(exampleUrl, exampleCookies)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		jar.Cookies(updateUrl)
	}
}

// from half full jar
func BenchmarkGetNexHalfJar(b *testing.B) {
	b.StopTimer()
	jar := &Jar{}
	fillJar(jar, 0.75, 0.75)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		jar.Cookies(updateUrl)
	}
}

// from completely full jar
func BenchmarkGetNexFullJar(b *testing.B) {
	b.StopTimer()
	jar := &Jar{}
	fillJar(jar, 1, 1)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		jar.Cookies(updateUrl)
	}
}

// --------------------------------------------------------------------------
// Applicatin Usage

// AppUsage is: 
//   - Log into two different sites, recieve cookie
//   - work with these two domain, two subdomains thereof and two more sites
//   - get a cooke update
//   - do some work again
// where "work" is 50 plain requests each
func BenchmarkAppUsageFlatJar(b *testing.B) {
	host1, _ := url.Parse("http://www.host1.com")
	sub1, _ := url.Parse("http://abc.host1.com")
	host2, _ := url.Parse("http://www.host2.biz")
	sub2, _ := url.Parse("http://xyz.host2.biz")
	host3, _ := url.Parse("http://www.host3.org")
	host4, _ := url.Parse("http://www.host4.net")
	cookies := []*http.Cookie{
		&http.Cookie{Name: "nameA", Value: "value1", MaxAge: 600},
		&http.Cookie{Name: "nameB", Value: "value2", Domain: "host1.com"},
		&http.Cookie{Name: "nameC", Value: "value3"},
		&http.Cookie{Name: "nameD", Value: "value4", Domain: "host2.biz", MaxAge: 600},
	}

	for i := 0; i < b.N; i++ {
		jar := NewJar(cfgFlat)
		for k := 0; k < 5; k++ {
			jar.SetCookies(host1, cookies)
			jar.SetCookies(host2, cookies)
			for j := 0; j < 50; j++ {
				if len(jar.Cookies(host1)) != 3 {
					b.Errorf("Got %v", jar.Cookies(host1))
				}
				if len(jar.Cookies(sub1)) != 1 {
					b.Errorf("Got %v", jar.Cookies(sub2))
				}
				if len(jar.Cookies(host2)) != 3 {
					b.Errorf("Got %v", jar.Cookies(host2))
				}
				if len(jar.Cookies(sub2)) != 1 {
					b.Errorf("Got %v", jar.Cookies(sub2))
				}
				if len(jar.Cookies(host3)) != 0 {
					b.Errorf("Got %v", jar.Cookies(host3))
				}
				if len(jar.Cookies(host4)) != 0 {
					b.Errorf("Got %v", jar.Cookies(host4))
				}
			}
		}
	}
}

func BenchmarkAppUsageFancyJar(b *testing.B) {
	host1, _ := url.Parse("http://www.host1.com")
	sub1, _ := url.Parse("http://abc.host1.com")
	host2, _ := url.Parse("http://www.host2.biz")
	sub2, _ := url.Parse("http://xyz.host2.biz")
	host3, _ := url.Parse("http://www.host3.org")
	host4, _ := url.Parse("http://www.host4.net")
	cookies := []*http.Cookie{
		&http.Cookie{Name: "nameA", Value: "value1", MaxAge: 600},
		&http.Cookie{Name: "nameB", Value: "value2", Domain: "host1.com"},
		&http.Cookie{Name: "nameC", Value: "value3"},
		&http.Cookie{Name: "nameD", Value: "value4", Domain: "host2.biz", MaxAge: 600},
	}

	for i := 0; i < b.N; i++ {
		jar := NewJar(cfgFancy)
		for k := 0; k < 5; k++ {
			jar.SetCookies(host1, cookies)
			jar.SetCookies(host2, cookies)
			for j := 0; j < 50; j++ {
				if len(jar.Cookies(host1)) != 3 {
					b.Errorf("Got %v", jar.Cookies(host1))
				}
				if len(jar.Cookies(sub1)) != 1 {
					b.Errorf("Got %v", jar.Cookies(sub2))
				}
				if len(jar.Cookies(host2)) != 3 {
					b.Errorf("Got %v", jar.Cookies(host2))
				}
				if len(jar.Cookies(sub2)) != 1 {
					b.Errorf("Got %v", jar.Cookies(sub2))
				}
				if len(jar.Cookies(host3)) != 0 {
					b.Errorf("Got %v", jar.Cookies(host3))
				}
				if len(jar.Cookies(host4)) != 0 {
					b.Errorf("Got %v", jar.Cookies(host4))
				}
			}
		}
	}
}


/*************


// The following are used to construct host names.  All should have different prime length.
var path = []string{"/", "/abc", "/abc/xyz", "/yuhu", "/yuhu/aloha"} // 5

var tld = []string{".com", ".net", ".org", ".info", ".biz", ".uk", ".de",
	".ai", ".ag", ".af", ".al", ".au", ".uk", ".gr", ".hk",
	".qr", ".st", ".uv", ".wx", ".yz", ".qw", ".as", ".er"} // 23
var tldp1 = []string{"foo", "bar", "baz", "qux", "co", "blob", "com",
	"wup", "long", "longer", "realy-very-long", "ugggglllly-lllloooonnnnnnng",
	"aaa", "bbb", "ccc", "ddd", "eee", "fff", "ggg", "hhh",
	"iii", "jjj", "kkk", "lll", "mmm", "gov", "edu", "org", "net"} // 29
var tldp2 = []string{"www.", "sso.", "info.", "aaa.", "bbb.", "ccc.", "d.",
	"e.", "f.", "g.", "h.", "i.", "j."} // 13
var names = []string{"session", "name", "foobar", "W_UzTzk", "x", "a", "b",
	"c", "d", "e", "f", "g", "h", "iiiiiiiiiii", "JJJJJJJJJJJJJ", "k",
	"l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "XXXXX",
	"YYYYYY", "ZzZzZz"} // 31

var hostPerc = flag.Int("host", 21, "make that percentage to host cookies")
var sessionPerc = flag.Int("session", 31, "make that percentage persistant")
var shortlivedPerc = flag.Int("mayfly", 29, "make that percentage of persistant cookie shortlived")

type uAndC struct {
	u *url.URL
	c []*http.Cookie
}

func prepare(n int) []uAndC {
	cookies := make([]uAndC, n)
	for i := 0; i < n; i++ {
		host := tldp2[i%len(tldp2)] + tldp1[i%len(tldp1)] + tld[i%len(tld)]

		cookie := http.Cookie{Name: names[i%len(names)], Value: "CookieValue", Path: path[i%len(path)]}
		if rand.Intn(100) < *hostPerc {
			cookie.Domain = "." + host
		}
		if rand.Intn(100) < *sessionPerc {
			if rand.Intn(100) < *shortlivedPerc {
				cookie.MaxAge = 2
			} else {
				cookie.MaxAge = 999999999
			}
		}

		cookies[i].u, _ = url.Parse("http://" + host)
		cookies[i].c = make([]*http.Cookie, 1)
		cookies[i].c[0] = &cookie
	}
	return cookies
}

func BenchmarkCreateCookies(b *testing.B) {
	b.StopTimer()
	cookies := prepare(b.N)
	jar := NewCustomJar(5000, 20000, 4096, true, true)

	b.StartTimer()
	for i := 0; i < b.N; i++ {
		jar.SetCookies(cookies[i].u, cookies[i].c)
	}
}

func BenchmarkUpdateCookies(b *testing.B) {
	b.StopTimer()
	cookies := prepare(b.N)
	jar := NewCustomJar(5000, 20000, 4096, true, true)

	// create
	for i := 0; i < b.N; i++ {
		jar.SetCookies(cookies[i].u, cookies[i].c)
	}
	for i := 0; i < b.N; i++ {
		cookies[i].c[0].Value = "NewValue"
	}

	b.StartTimer()
	for i := 0; i < b.N; i++ {
		jar.SetCookies(cookies[i].u, cookies[i].c)
	}
}

func BenchmarkDeleteCookies(b *testing.B) {
	b.StopTimer()
	cookies := prepare(b.N)
	jar := NewCustomJar(5000, 20000, 4096, true, true)

	// create
	for i := 0; i < b.N; i++ {
		jar.SetCookies(cookies[i].u, cookies[i].c)
	}
	for i := 0; i < b.N; i++ {
		cookies[i].c[0].MaxAge = -1
	}

	b.StartTimer()
	for i := 0; i < b.N; i++ {
		jar.SetCookies(cookies[i].u, cookies[i].c)
	}
}

func BenchmarkCookieRetrieval(b *testing.B) {
	b.StopTimer()
	cookies := prepare(b.N)
	jar := NewCustomJar(5000, 20000, 4096, true, true)
	for _, x := range cookies {
		jar.SetCookies(x.u, x.c)
	}
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		jar.Cookies(cookies[i].u)
	}
}
******************/
