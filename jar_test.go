// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cookiejar

import (
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

func (a updateAction) String() string {
	switch a {
	case invalidCookie:
		return "invalidCookie"
	case deleteCookie:
		return "deleteUnstored"
	case createCookie:
		return "createCookie"
	case updateCookie:
		return "updateCookie"
	}
	return "???"
}

var defaultPathTests = []struct{ path, dir string }{
	{"", "/"},
	{"xy", "/"},
	{"xy/z", "/"},
	{"/", "/"},
	{"/abc", "/"},
	{"/ab/xy", "/ab"},
	{"/ab/xy/z", "/ab/xy"},
	{"/ab/", "/ab"},
	{"/ab/xy/z/", "/ab/xy/z"},
}

func TestDefaultPath(t *testing.T) {
	for _, test := range defaultPathTests {
		u := url.URL{Path: test.path}
		got := defaultPath(&u)
		if got != test.dir {
			t.Errorf("Test %s want %s got %s", test.path, got, test.dir)
		}
	}
}

func TestPathMatch(t *testing.T) {
	for _, tt := range []struct {
		cookiePath, urlPath string
		match               bool
	}{
		{"/", "/", true},
		{"/x", "/x", true},
		{"/", "/abc", true},
		{"/abc", "/foo", false},
		{"/abc", "/foo/", false},
		{"/abc", "/abcd", false},
		{"/abc", "/abc/d", true},
		{"/path", "/", false},
		{"/path", "/path", true},
		{"/path", "/path/x", true},
	} {
		c := &Cookie{Path: tt.cookiePath}
		if c.pathMatch(tt.urlPath) != tt.match {
			t.Errorf("want %t for %s ~ %s", tt.match, tt.cookiePath, tt.urlPath)
		}
	}
}

var hostTests = []struct {
	in, expected string
}{
	{"www.example.com", "www.example.com"},
	{"www.EXAMPLE.com", "www.example.com"},
	{"wWw.eXAmple.CoM", "www.example.com"},
	{"www.example.com:80", "www.example.com"},
	{"12.34.56.78:8080", "12.34.56.78"},
}

func TestHost(t *testing.T) {
	for _, test := range hostTests {
		out, _ := host(&url.URL{Host: test.in})
		if out != test.expected {
			t.Errorf("Test %s got %s want %s", test.in, out, test.expected)
		}
	}
}

var isIPTests = []struct {
	host string
	isIP bool
}{
	{"example.com", false},
	{"127.0.0.1", true},
	{"1.1.1.300", false},
	{"www.foo.bar.net", false},
	{"123.foo.bar.net", false},
	// TODO: IPv6 test
}

func TestIsIP(t *testing.T) {
	for _, test := range isIPTests {
		if isIP(test.host) != test.isIP {
			t.Errorf("Test %s want %t", test.host, test.isIP)
		}
	}
}

var domainAndTypeTests = []struct {
	inHost, inCookieDomain string
	outDomain              string
	outHostOnly            bool
}{
	{"www.example.com", "", "www.example.com", true},
	{"127.www.0.0.1", "127.0.0.1", "", false},
	{"www.example.com", ".", "", false},
	{"www.example.com", "..", "", false},
	{"www.example.com", "com", "", false},
	{"www.example.com", ".com", "", false},
	{"www.example.com", "example.com", "example.com", false},
	{"www.example.com", ".example.com", "example.com", false},
	{"www.example.com", "www.example.com", "www.example.com", false},  // Unsure abou this and
	{"www.example.com", ".www.example.com", "www.example.com", false}, // this one.
	{"foo.sso.example.com", "sso.example.com", "sso.example.com", false},
}

func TestDomainAndType(t *testing.T) {
	jar := Jar{}
	for _, test := range domainAndTypeTests {
		d, h := jar.domainAndType(test.inHost, test.inCookieDomain)
		if d != test.outDomain || h != test.outHostOnly {
			t.Errorf("Test %s/%s want %s/%t got %s/%t",
				test.inHost, test.inCookieDomain,
				test.outDomain, test.outHostOnly, d, h)
		}
	}
}

func TestStrictnessWithIP(t *testing.T) {
	// No (host cookies) for IP addresses in strict mode
	jar := &Jar{MaxCookiesPerDomain: 10, MaxCookiesTotal: 10, MaxBytesPerCookie: 10}
	d, h := jar.domainAndType("127.0.0.1", "127.0.0.1")
	if d != "" {
		t.Errorf("Got %s", d)
	}

	// Allow host cookies for IP addresses like IE, FF and Chrome
	// if non-strict jar.
	jar = &Jar{MaxCookiesPerDomain: 10, MaxCookiesTotal: 10, MaxBytesPerCookie: 10, LaxMode: true}
	d, h = jar.domainAndType("127.0.0.1", "127.0.0.1")
	if d != "127.0.0.1" || h != true {
		t.Errorf("Got %s and %t", d, h)
	}

	runJarTest(t, jar, jarTest{"http://1.2.3.4/weee",
		"TestIpAddress domain cookies for exact match",
		[]string{"b=2; domain=1.2.3.4"},
		[]expect{{"http://1.2.3.4/weee", "b=2"}},
	})

	// Totaly unsure about this one:
	// RFC 6265 forbidds cookies on IP addresses, in non strict mode
	// we allow them if IP-address == Domain attribute (which
	// it is _not_ here due to leading dot).  But RFC 6265 request
	// striping of a leading dot during parsing of cookie which
	// would indicate that we would see 1.2.3.4 without dot when
	// deciding what to do, so we migt in non-strict mode....
	/*
		runJarTest(t, jar, jarTest{"http://1.2.3.4/weee",
			"TestIpAddress but no domain cookies",
			[]string{"b=2; domain=.1.2.3.4", "c=3; domain=.3.4"}, 
			[]expect{{"http://1.2.3.4/weee", ""}},
		})
	*/
}

// -------------------------------------------------------------------------
// Update

type updateTest struct {
	// elements of url
	uscheme, uhost, upath string // what name suggest

	// elements of cookie
	cname, cvalue  string // what the name suggests
	cpath, cdomain string // what the name suggests
	cexp           int    // cexp==0: no Expires; else delta to now in sec
	cmaxage        int    // what name suggests
	csecure, chttp bool   // what name suggests

	// expected results
	eaction        updateAction
	edomain, epath string
	eexp           int // eexp==-999 session cookie; else delta to now in sec
	ehostonly      bool
}

// cookie names (cname) must be unique to allow present() to find them!
var updateTests = []updateTest{
	// cookies which get strored
	{"http", "www.example.org", "",
		"first", "firstV", "", "", 0, 0, false, false,
		createCookie, "www.example.org", "/", -999, true},
	{"http", "www.example.org", "/some/path/here.html",
		"second", "secondV", "", "", 0, 0, false, false,
		createCookie, "www.example.org", "/some/path", -999, true},
	{"http", "www.example.org", "/some/path/here.html",
		"third", "thirdV", "/other/path", "", 0, 0, false, false,
		createCookie, "www.example.org", "/other/path", -999, true},
	{"http", "www.example.org", "/some/path/here.html",
		"forth", "fourthV", "badpath", "", 600, 0, false, false,
		createCookie, "www.example.org", "/some/path", 600, true},
	{"http", "www.test.net", "/foo/bar/",
		"fifth", "fifthV", "", ".test.net", 200, 100, false, false,
		createCookie, "test.net", "/foo/bar", 100, false},
	{"http", "bar.www.test.net", "/xyz",
		"sixth", "sixthV", "/foo/bar", "www.test.net", 200, 100, false, false,
		createCookie, "www.test.net", "/foo/bar", 100, false},

	// cookies which are rejected
	{"http", "www.example.org", "",
		"rej1", "rej1V", "", ".org", 0, 0, false, false,
		invalidCookie, "", "", 0, false},
	{"http", "www.example.org", "",
		"rej2", "rej2V", "", "wexample.org", 0, 0, false, false,
		invalidCookie, "", "", 0, false},
	{"http", "www.example.org", "",
		"rej3", "rej3V", "", "foo.example.org", 0, 0, false, false,
		invalidCookie, "", "", 0, false},

	// cookies which are deleted
	{"http", "www.example.org", "",
		"first", "firstV", "", "", -123, 0, false, false,
		deleteCookie, "", "", 0, false},
	{"http", "www.example.org", "",
		"first", "firstV", "", "", -123, 0, false, false,
		deleteCookie, "", "", 0, false},
	{"http", "www.example.org", "",
		"first", "firstV", "", "", 0, -123, false, false,
		deleteCookie, "", "", 0, false},
	{"http", "www.example.org", "/some/path/here.html",
		"second", "secondV", "", "", 234, -123, false, false,
		deleteCookie, "", "", 0, false},
	{"http", "www.example.org", "/some/path/here.html",
		"second", "secondV", "", "", 234, -123, false, false,
		deleteCookie, "", "", 0, false},
	{"http", "www.example.org", "/some/path/here.html",
		"second", "secondV", "", "", -234, 0, false, false,
		deleteCookie, "", "", 0, false},
	{"http", "www.example.org", "/some/path/here.html",
		"second", "secondV", "", "", -234, -123, false, false,
		deleteCookie, "", "", 0, false},
	{"http", "www.example.org", "/some/path/here.html",
		"second", "secondV", "", "", 0, -123, false, false,
		deleteCookie, "", "", 0, false},
}

func present(jar *Jar, tt updateTest, now time.Time, t *testing.T) bool {
	// blunt search over everything
	for _, c := range jar.cookies {
		if c.Name != tt.cname {
			continue
		}

		if c.Value != tt.cvalue {
			t.Errorf("Cookie %s got value %s want %s", tt.cname, c.Value, tt.cvalue)
		}
		if c.Domain != tt.edomain {
			t.Errorf("Cookie %s got domain %s want %s", tt.cname, c.Domain, tt.edomain)
		}
		if c.HostOnly != tt.ehostonly {
			t.Errorf("Cookie %s got hostonly %t want %t", tt.cname, c.HostOnly, tt.ehostonly)
		}
		if c.Path != tt.epath {
			t.Errorf("Cookie %s got path %s want %s", tt.cname, c.Path, tt.epath)
		}
		if tt.eexp == -999 && !c.Expires.IsZero() {
			t.Errorf("Cookie %s got persisten cookie with ttl %d s want session cookie",
				tt.cname, int(c.Expires.Sub(now).Seconds()))
		}
		if tt.eexp != -999 && now.Add(time.Duration(tt.eexp)*time.Second) != c.Expires {
			t.Errorf("Cookie %s got persistent cookie with ttl %d s want ttl of %d",
				tt.cname, int(c.Expires.Sub(now).Seconds()), tt.eexp)

		}
		return true
	}
	return false
}

func TestUpdate(t *testing.T) {
	jar := &Jar{}

	now := time.Now()
	for _, tt := range updateTests {
		u := &url.URL{Scheme: tt.uscheme, Host: tt.uhost, Path: tt.upath}

		var exp time.Time
		if tt.cexp != 0 {
			exp = now
			exp = exp.Add(time.Second * time.Duration(tt.cexp))
		}
		if tt.cmaxage != 0 {
			exp = now
			exp = exp.Add(time.Second * time.Duration(tt.cmaxage))
		}
		cookie := &http.Cookie{Name: tt.cname, Value: tt.cvalue,
			Path: tt.cpath, Domain: tt.cdomain, Expires: exp,
			MaxAge: tt.cmaxage, Secure: tt.csecure, HttpOnly: tt.chttp}

		defaultPath := defaultPath(u)

		action := jar.update(tt.uhost, defaultPath, now, cookie)

		if action != tt.eaction {
			t.Errorf("Test cookie named %s got action %s want %s",
				tt.cname, action, tt.eaction)
		} else {
			switch tt.eaction {
			case createCookie, updateCookie:
				if !present(jar, tt, now, t) {
					t.Errorf("Test cookie named %s not found after store", tt.cname)
				}
			case deleteCookie:
				if present(jar, tt, now, t) {
					t.Errorf("Test cookie named %s found after store", tt.cname)
				}
			}
		}

	}
}

// -------------------------------------------------------------------------
// The Big Jar Test

// all the cookies we expect to get back on a jar.Cookies(toUrl)
type expect struct {
	toUrl   string // url to send to
	cookies string // the serialization of the cookies
}

// The input to a jar.SetCookie(requestUrl, setCookies) and our expectation
// on what to get back directly afterwards.
type jarTest struct {
	requestUrl  string   // the full url of the request to which Set-Cookie headers where recieved
	description string   // the description of whats tests
	setCookies  []string // all the cookies we set as simplified (see below) cookie header lines
	expected    []expect // what to expect, again as a cookie header line
}

// The following tests must be perfomed on an empty jar each.
var singleJarTests = []jarTest{
	{"http://www.host.test/", "Simple Test, Base Test",
		[]string{"A=a"},
		[]expect{
			{"http://www.host.test", "A=a"},
			{"http://www.host.test/", "A=a"},
			{"http://www.host.test/some/path", "A=a"},
			{"https://www.host.test", "A=a"},
			{"https://www.host.test/", "A=a"},
			{"https://www.host.test/some/path", "A=a"},
			/*  we're a http only jar ...
			{"ftp://www.host.test", "A=a"},
			{"ftp://www.host.test/", "A=a"},
			{"ftp://www.host.test/some/path", "A=a"},
			*/
			{"http://www.other.org", ""},
			{"http://sibling.host.test", ""},
			{"http://deep.www.host.test", ""},
		},
	},
	{"http://www.host.test/", "HttpOnly Cookies",
		[]string{"A=a; httponly"},
		[]expect{
			{"http://www.host.test", "A=a"},
			{"http://www.host.test/", "A=a"},
			{"http://www.host.test/some/path", "A=a"},
			{"https://www.host.test", "A=a"},
			{"https://www.host.test/", "A=a"},
			{"https://www.host.test/some/path", "A=a"},
			{"ftp://www.host.test", ""},
			{"ftp://www.host.test/", ""},
			{"ftp://www.host.test/some/path", ""},
			{"http://www.other.org", ""},
			{"http://sibling.host.test", ""},
			{"http://deep.www.host.test", ""},
		},
	},
	{"http://www.host.test/", "Secure + HttpOnly cookie",
		[]string{"A=a; secure; httponly"},
		[]expect{
			{"http://www.host.test", ""},
			{"http://www.host.test/", ""},
			{"http://www.host.test/some/path", ""},
			{"https://www.host.test", "A=a"},
			{"https://www.host.test/", "A=a"},
			{"https://www.host.test/some/path", "A=a"},
			{"ftp://www.host.test", ""},
			{"ftp://www.host.test/", ""},
			{"ftp://www.host.test/some/path", ""},
			{"http://www.other.org", ""},
			{"http://sibling.host.test", ""},
			{"http://deep.www.host.test", ""},
		},
	},
	{"http://www.host.test/", "Secure cookie",
		[]string{"A=a; secure"},
		[]expect{
			{"http://www.host.test", ""},
			{"http://www.host.test/", ""},
			{"http://www.host.test/some/path", ""},
			{"https://www.host.test", "A=a"},
			{"https://www.host.test/", "A=a"},
			{"https://www.host.test/some/path", "A=a"},
			{"ftp://www.host.test", ""},
			{"ftp://www.host.test/", ""},
			{"ftp://www.host.test/some/path", ""},
			{"http://www.other.org", ""},
			{"http://sibling.host.test", ""},
			{"http://deep.www.host.test", ""},
		},
	},
	{"http://www.host.test/", "Explicit path",
		[]string{"A=a; path=/some/path"},
		[]expect{
			{"http://www.host.test", ""},
			{"http://www.host.test/", ""},
			{"http://www.host.test/some", ""},
			{"http://www.host.test/some/", ""},
			{"http://www.host.test/some/path", "A=a"},
			{"http://www.host.test/some/paths", ""},
			{"http://www.host.test/some/path/foo", "A=a"},
			{"http://www.host.test/some/path/foo/", "A=a"},
		},
	},
	{"http://www.host.test/some/path/", "Implicit path v1: path is directoy",
		[]string{"A=a"},
		[]expect{
			{"http://www.host.test", ""},
			{"http://www.host.test/", ""},
			{"http://www.host.test/some", ""},
			{"http://www.host.test/some/", ""},
			{"http://www.host.test/some/path", "A=a"},
			{"http://www.host.test/some/paths", ""},
			{"http://www.host.test/some/path/foo", "A=a"},
			{"http://www.host.test/some/path/foo/", "A=a"},
		},
	},
	{"http://www.host.test/some/path/index.html", "Implicit path v2: path not directory",
		[]string{"A=a"},
		[]expect{
			{"http://www.host.test", ""},
			{"http://www.host.test/", ""},
			{"http://www.host.test/some", ""},
			{"http://www.host.test/some/", ""},
			{"http://www.host.test/some/path", "A=a"},
			{"http://www.host.test/some/paths", ""},
			{"http://www.host.test/some/path/foo", "A=a"},
			{"http://www.host.test/some/path/foo/", "A=a"},
		},
	},
	{"http://www.host.test", "Implicit path v3: no path in url at all",
		[]string{"A=a"},
		[]expect{
			{"http://www.host.test", "A=a"},
			{"http://www.host.test/", "A=a"},
			{"http://www.host.test/some/path", "A=a"},
		},
	},
	{"http://www.host.test/", "Sort returned cookies by path length",
		[]string{"A=a; path=/foo/bar", "B=b; path=/foo/bar/baz/qux",
			"C=c; path=/foo/bar/baz", "D=d; path=/foo"},
		[]expect{
			{"http://www.host.test/foo/bar/baz/qux", "B=b; C=c; A=a; D=d"},
		},
	},
	{"http://www.test.org/", "Same name, different cookie",
		[]string{"A=1; path=/",
			"A=2; path=/path",
			"A=3; path=/quux",
			"A=4; path=/path/foo",
			"A=5; domain=.test.org; path=/path",
			"A=6; domain=.test.org; path=/quux",
			"A=7; domain=.test.org; path=/path/foo",
		},
		[]expect{
			{"http://www.test.org/path", "A=2; A=5; A=1"},
			{"http://www.test.org/path/foo", "A=4; A=7; A=2; A=5; A=1"},
		},
	},
	//
	// Test from http://src.chromium.org/viewvc/chrome/trunk/src/net/base/cookie_monster_unittest.cc
	// 
	{"http://www.google.com/", "DomainWithTrailingDotTest",
		[]string{"a=1; domain=.www.google.com.", "a=1; domain=.www.google.com.."},
		[]expect{
			{"http://www.google.com", ""},
		},
	},
	{"http://a.b.c.d.com", "ValidSubdomainTest",
		[]string{"a=1; domain=.a.b.c.d.com", "b=2; domain=.b.c.d.com",
			"c=3; domain=.c.d.com", "d=4; domain=.d.com"},
		[]expect{
			{"http://a.b.c.d.com", "a=1; b=2; c=3; d=4"},
			{"http://b.c.d.com", "b=2; c=3; d=4"},
			{"http://c.d.com", "c=3; d=4"},
			{"http://d.com", "d=4"},
		},
	},
	{"http://a.b.c.d.com", "ValidSubdomainTest part 2",
		[]string{"a=1; domain=.a.b.c.d.com", "b=2; domain=.b.c.d.com",
			"c=3; domain=.c.d.com", "d=4; domain=.d.com",
			"X=bcd; domain=.b.c.d.com", "X=cd; domain=.c.d.com"},
		[]expect{
			{"http://b.c.d.com", "b=2; c=3; d=4; X=bcd; X=cd"},
			{"http://c.d.com", "c=3; d=4; X=cd"},
		},
	},
	{"http://foo.bar.com", "InvalidDomainTest",
		[]string{"a=1; domain=.yo.foo.bar.com",
			"b=2; domain=.foo.com",
			"c=3; domain=.bar.foo.com",
			"d=4; domain=.foo.bar.com.net",
			"e=5; domain=ar.com",
			"f=6; domain=.",
			"g=7; domain=/",
			"h=8; domain=http://foo.bar.com",
			"i=9; domain=..foo.bar.com",
			"j=10; domain=..bar.com",
			"k=11; domain=.foo.bar.com?blah",
			"l=12; domain=.foo.bar.com/blah",
			"m=12; domain=.foo.bar.com:80",
			"n=14; domain=.foo.bar.com:",
			"o=15; domain=.foo.bar.com#sup",
		},
		[]expect{{"http://foo.bar.com", ""}},
	},
	{"http://foo.com.com", "InvalidDomainTest part 2",
		[]string{"a=1; domain=.foo.com.com.com"},
		[]expect{{"http://foo.bar.com", ""}},
	},
	{"http://manage.hosted.filefront.com", "DomainWithoutLeadingDotTest 1",
		[]string{"A=a; domain=filefront.com"},
		[]expect{{"http://www.filefront.com", "A=a"}},
	},
	{"http://www.google.com", "DomainWithoutLeadingDotTest 2",
		[]string{"a=1; domain=www.google.com"},
		[]expect{
			{"http://www.google.com", "a=1"},
			{"http://sub.www.google.com", "a=1"},
			{"http://something-else.com", ""},
		},
	},
	{"http://www.google.com", "CaseInsensitiveDomainTest",
		[]string{"a=1; domain=.GOOGLE.COM", "b=2; domain=.www.gOOgLE.coM"},
		[]expect{{"http://www.google.com", "a=1; b=2"}},
	},
	{"http://1.2.3.4/weee", "TestIpAddress",
		[]string{"A=B; path=/"},
		[]expect{{"http://1.2.3.4/weee", "A=B"}},
	},
	{"http://com/", "TestNonDottedAndTLD: allow on com but only as host cookie",
		[]string{"a=1", "b=2; domain=.com", "c=3; domain=com"},
		[]expect{
			{"http://com/", "a=1"},
			{"http://no-cookies.com/", ""},
			{"http://.com/", ""},
		},
	},
	{"http://com./index.html", "TestNonDottedAndTLD: treat com. same as com",
		[]string{"a=1"},
		[]expect{
			{"http://com./index.html", "a=1"},
			{"http://no-cookies.com./index.html", ""},
		},
	},
	{"http://a.b", "TestNonDottedAndTLD: cannot set host cookie from subdomain",
		[]string{"a=1; domain=.b", "b=2; domain=b"},
		[]expect{{"http://a.b", ""}},
	},
	{"http://google.com", "TestNonDottedAndTLD: same as above but for known TLD (com)",
		[]string{"a=1; domain=.com", "b=2; domain=com"},
		[]expect{{"http://google.com", ""}},
	},
	{"http://google.co.uk", "TestNonDottedAndTLD: cannot set on TLD which is dotted",
		[]string{"a=1; domain=.co.uk", "b=2; domain=.uk"},
		[]expect{
			{"http://google.co.uk", ""},
			{"http://else.co.com", ""},
			{"http://else.uk", ""},
		},
	},
	{"http://b", "TestNonDottedAndTLD: intranet URLs may set host cookies only",
		[]string{"a=1", "b=2; domain=.b", "c=3; domain=b"},
		[]expect{{"http://b", "a=1"}},
	},
	{"http://www.google.izzle", "PathTest",
		[]string{"A=B; path=/wee"},
		[]expect{
			{"http://www.google.izzle/wee", "A=B"},
			{"http://www.google.izzle/wee/", "A=B"},
			{"http://www.google.izzle/wee/war", "A=B"},
			{"http://www.google.izzle/wee/war/more/more", "A=B"},
			{"http://www.google.izzle/weehee", ""},
			{"http://www.google.izzle/", ""},
		},
	},
}

func TestSingleJar(t *testing.T) {
	for _, tt := range singleJarTests {
		jar := &Jar{}
		runJarTest(t, jar, tt)
	}
}

// The following must be run in one batch against one jar each
var groupedJarTests = [][]jarTest{
	[]jarTest{
		{"http://www.example.com", "Set some initial cookies",
			[]string{"a=1", "b=2; secure", "c=3; httponly", "d=4; secure; httponly"},
			[]expect{
				{"http://www.example.com", "a=1; c=3"},
				{"https://www.example.com", "a=1; b=2; c=3; d=4"},
			},
		},
		/*  we're a http only jar....
		{"ftp://www.example.com", "Cannot update HttpOnly cookie via ftp",
			[]string{"a=11", "b=22; secure", "c=33; httponly", "d=44; secure; httponly"},
			[]expect{
				{"http://www.example.com", "a=11; c=3"},
				{"https://www.example.com", "a=11; b=22; c=3; d=4"},
			},
		},
		*/
		{"http://www.example.com", "We can update all of them to new value via http",
			[]string{"a=w", "b=x; secure", "c=y; httponly", "d=z; secure; httponly"},
			[]expect{
				{"http://www.example.com", "a=w; c=y"},
				{"https://www.example.com", "a=w; b=x; c=y; d=z"},
			},
		},
		{"http://www.example.com/", "We can clear a Secure flag from a http request",
			[]string{"b=xx", "d=zz; httponly"},
			[]expect{{"http://www.example.com", "a=w; b=xx; c=y; d=zz"}},
		},
		{"http://www.example.com/", "We can delete all of them",
			[]string{"a=1; 0", //  delete via MaxAge
				"b=2; -1",  // delete via Expires
				"c=2; -2",  // delete via both
				"d=4; -3"}, // Expires in futere but delete via MaxAge<0
			[]expect{{"http://www.example.com", ""}},
		},
	},
	// Tests from http://src.chromium.org/viewvc/chrome/trunk/src/net/base/cookie_monster_unittest.cc
	[]jarTest{
		// 
		{"http://www.google.com", "TestHostEndsWithDot 1",
			[]string{"a=1"},
			[]expect{{"http://www.google.com", "a=1"}},
		},
		{"http://www.google.com", "TestHostEndsWithDot 2",
			[]string{"b=2; domain=.www.google.com."},
			[]expect{{"http://www.google.com", "a=1"}},
		},
		{"http://www.google.com.", "TestHostEndsWithDot 3",
			[]string{"b=2; domain=.google.com."},
			[]expect{{"http://www.google.com.", "b=2"}},
		},
	},
	[]jarTest{
		{"http://www.google.com", "TestCookieDeletion: Create session cookie",
			[]string{"a=1"},
			[]expect{{"http://www.google.com", "a=1"}},
		},
		{"http://www.google.com", "TestCookieDeletion: Delete sc via MaxAge",
			[]string{"a=1; 0"},
			[]expect{{"http://www.google.com", ""}},
		},
		{"http://www.google.com", "TestCookieDeletion: Create session cookie2",
			[]string{"b=2"},
			[]expect{{"http://www.google.com", "b=2"}},
		},
		{"http://www.google.com", "TestCookieDeletion: Delete sc 2 via Expires",
			[]string{"b=2; -1"},
			[]expect{{"http://www.google.com", ""}},
		},

		{"http://www.google.com", "TestCookieDeletion: Create persistent cookie",
			[]string{"c=3; 401"},
			[]expect{{"http://www.google.com", "c=3"}},
		},
		{"http://www.google.com", "TestCookieDeletion: Delete pc via MaxAge",
			[]string{"c=3; 0"},
			[]expect{{"http://www.google.com", ""}},
		},
		{"http://www.google.com", "TestCookieDeletion: Create persistant cookie2",
			[]string{"d=4; 401"},
			[]expect{{"http://www.google.com", "d=4"}},
		},
		{"http://www.google.com", "TestCookieDeletion: Delete pc 2 via Expires",
			[]string{"d=4; -1"},
			[]expect{{"http://www.google.com", ""}},
		},
	},
}

func TestGroupedJar(t *testing.T) {
	for _, ttt := range groupedJarTests {
		jar := &Jar{}
		for _, tt := range ttt {
			runJarTest(t, jar, tt)
		}
	}
}

func runJarTest(t *testing.T, jar *Jar, test jarTest) {
	u, err := url.Parse(test.requestUrl)
	if err != nil {
		t.Fatalf("Unable to parse URL %s: %s", test.requestUrl, err.Error())
	}

	setcookies := make([]*http.Cookie, len(test.setCookies))
	for i, cs := range test.setCookies {
		setcookies[i] = parseCookie(cs)
	}
	jar.SetCookies(u, setcookies)

	for _, exp := range test.expected {
		u, err := url.Parse(exp.toUrl)
		if err != nil {
			t.Fatalf("Unable to parse URL %s: %s", test.requestUrl, err.Error())
		}
		cookies := jar.Cookies(u)
		cs := make([]string, len(cookies))
		for i, c := range cookies {
			cs[i] = c.String()
		}
		serialized := strings.Join(cs, "; ")

		if serialized != exp.cookies {
			t.Errorf("Test %s: %s\nGot  %s\nWant %s",
				test.description, exp.toUrl, serialized, exp.cookies)
		}
	}

}

// check if cs is contained in cookies.  cs has the format
//    name [ '=' value ]
// returns index into cookies or -1
func index(cookies []*http.Cookie, cs string) int {
	var name, value string
	name = cs
	if i := strings.Index(cs, "="); i != -1 {
		name, value = cs[:i], cs[i+1:]
		fmt.Printf("name=%s value=%s\n", name, value)
	}

	for idx, c := range cookies {
		if c.Name != name {
			continue
		}
		if value != "" && c.Value != value {
			fmt.Printf("bad value %s\n", c.Value)
			continue
		}
		fmt.Printf("found\n")
		return idx
	}
	return -1
}

// not a full fletched parser, but enough for our testcases. Format is
//    A=a; domain=xyz.com; path=/; secure; httponly; 34
// Last integer is time to live and gets encoded the following way:
//    ttl%4 == 0   -->  MaxAge=ttl
//    ttl%4 == 1   -->  Expires=NOW+ttl
//    ttl%4 == 2   -->  MaxAge=ttl; Expires=NOW+ttl
//    ttl%4 == 3   -->  MaxAge=ttl; Expires=NOW-ttl
func parseCookie(s string) *http.Cookie {
	ss := strings.Split(s, "; ")
	ab := strings.Split(ss[0], "=")

	cookie := &http.Cookie{Name: ab[0], Value: ab[1]}
	for _, part := range ss[1:] {
		kv := strings.Split(part, "=")
		switch kv[0] {
		case "domain":
			cookie.Domain = kv[1]
		case "path":
			cookie.Path = kv[1]
		case "secure":
			cookie.Secure = true
		case "httponly":
			cookie.HttpOnly = true
		default:
			sec, err := strconv.Atoi(kv[0])
			if err != nil {
				panic("Bad cookie line " + s)
			}
			mode := sec % 4
			if mode < 0 {
				mode = -mode
			}
			if mode != 2 {
				if sec <= 0 {
					cookie.MaxAge = -1
				} else {
					cookie.MaxAge = sec
				}
			}
			if mode == 1 || mode == 2 {
				cookie.Expires = time.Now().Add(time.Duration(sec) * time.Second)
			} else if mode == 3 {
				cookie.Expires = time.Now().Add(time.Duration(-sec) * time.Second)
			}
		}
	}
	return cookie
}

// -------------------------------------------------------------------------
// Housekeeping

// serialize all cookie names into one string after sorting names
// e.g. "a;b;x"
func (jar *Jar) allNames() string {
	names := make([]string, len(jar.cookies))
	for i, c := range jar.cookies {
		names[i] = c.Name
	}
	sort.Strings(names)
	return strings.Join(names, ";")
}

func TestMaxTotal(t *testing.T) {
	jar := &Jar{MaxCookiesPerDomain: 100, MaxCookiesTotal: 3} // at most 3 cookies in total in jar
	u, _ := url.Parse("http://www.example.com")

	// fill up to capacity
	jar.SetCookies(u, []*http.Cookie{
		&http.Cookie{Name: "a", Value: "1"},
		&http.Cookie{Name: "b", Value: "2"},
		&http.Cookie{Name: "c", Value: "3"},
	})
	if jar.allNames() != "a;b;c" {
		t.Errorf("Initial. Have %s", jar.allNames())
	}

	// adding one should drop one
	jar.SetCookies(u, []*http.Cookie{&http.Cookie{Name: "d", Value: "4"}})
	if jar.allNames() != "b;c;d" {
		t.Errorf("Add one. Have %s", jar.allNames())
	}

	// adding 4
	jar.SetCookies(u, []*http.Cookie{
		&http.Cookie{Name: "e", Value: "5"},
		&http.Cookie{Name: "f", Value: "6"},
		&http.Cookie{Name: "g", Value: "7"},
		&http.Cookie{Name: "h", Value: "8"},
	})
	if jar.allNames() != "f;g;h" {
		t.Errorf("Add four. Have %s", jar.allNames())
	}

	// deleting one
	jar.SetCookies(u, []*http.Cookie{&http.Cookie{Name: "g", MaxAge: -1}})
	if jar.allNames() != "f;h" {
		t.Errorf("Delete one. Have %s", jar.allNames())
	}

	// adding one should be okay
	jar.SetCookies(u, []*http.Cookie{&http.Cookie{Name: "i", Value: "9"}})
	if jar.allNames() != "f;h;i" {
		t.Errorf("Add one 2. Have %s", jar.allNames())
	}
}

func TestMaxPerDomain(t *testing.T) {
	jar := &Jar{MaxCookiesPerDomain: 2, MaxCookiesTotal: 100} // at most 2 cookies per domain
	u1, _ := url.Parse("http://first.domain")
	u2, _ := url.Parse("http://second.domain")
	u3, _ := url.Parse("http://third.domain")
	// u4, _ := url.Parse("http://fourth.domain")

	// fill up to capacity with ...
	// ... host cookies for 1
	jar.SetCookies(u1, []*http.Cookie{
		&http.Cookie{Name: "a", Value: "1", Domain: ""},
		&http.Cookie{Name: "b", Value: "2", Domain: ""},
	})

	// ... domain cookies for 2
	jar.SetCookies(u2, []*http.Cookie{
		&http.Cookie{Name: "c", Value: "3", Domain: "second.domain"},
		&http.Cookie{Name: "d", Value: "4", Domain: "second.domain"},
	})
	// ... mix for 3
	jar.SetCookies(u3, []*http.Cookie{
		&http.Cookie{Name: "e", Value: "5", Domain: ""},
		&http.Cookie{Name: "f", Value: "6", Domain: "third.domain"},
	})
	if jar.allNames() != "a;b;c;d;e;f" {
		t.Errorf("Initial. Have %s", jar.allNames())
	}

	// adding to third
	jar.SetCookies(u3, []*http.Cookie{&http.Cookie{Name: "g", Value: "7"}})
	if jar.allNames() != "a;b;c;d;f;g" {
		t.Errorf("Add to third.domain. Have %s", jar.allNames())
	}

	// adding to second
	jar.SetCookies(u2, []*http.Cookie{&http.Cookie{Name: "h", Value: "8"}})
	if jar.allNames() != "a;b;d;f;g;h" {
		t.Errorf("Add to second.domain. Have %s", jar.allNames())
	}

	// adding to first
	jar.SetCookies(u1, []*http.Cookie{
		&http.Cookie{Name: "i", Value: "9", Domain: ""},
		&http.Cookie{Name: "j", Value: "10", Domain: "first.domain"},
	})
	if jar.allNames() != "d;f;g;h;i;j" {
		t.Errorf("Add to first.domain. Have %s", jar.allNames())
	}
}

func TestExpiresCleanup(t *testing.T) {
	jar := Jar{}
	u, _ := url.Parse("http://www.example.com")

	// fill up some cookies 
	jar.SetCookies(u, []*http.Cookie{
		&http.Cookie{Name: "a", Value: "1"},
		&http.Cookie{Name: "b", Value: "2", MaxAge: 1},
		&http.Cookie{Name: "c", Value: "3"},
		&http.Cookie{Name: "d", Value: "4", MaxAge: 1},
		&http.Cookie{Name: "e", Value: "5", MaxAge: 10000},
		&http.Cookie{Name: "f", Value: "6", MaxAge: 1},
	})
	if jar.allNames() != "a;b;c;d;e;f" {
		t.Errorf("Initial. Have %s", jar.allNames())
	}

	time.Sleep(1100 * time.Millisecond) // should expire b, d and f
	jar.SetCookies(u, []*http.Cookie{&http.Cookie{Name: "g", Value: "7"}})
	if jar.allNames() != "a;c;e;g" {
		t.Errorf("After 1.1 sec. Have %s", jar.allNames())
	}

}

func TestHonourLastAccesInCleanup(t *testing.T) {
	jar := &Jar{MaxCookiesPerDomain: 100, MaxCookiesTotal: 6} // at most 6 cookies  
	u, _ := url.Parse("http://www.example.com")
	uB, _ := url.Parse("http://www.example.com/B/too")

	// fill up some cookies with different path to allow different access
	jar.SetCookies(u, []*http.Cookie{
		&http.Cookie{Name: "a", Value: "1", Path: "/A"},
		&http.Cookie{Name: "b", Value: "2", Path: "/B"},
		&http.Cookie{Name: "c", Value: "3", Path: "/A"},
		&http.Cookie{Name: "d", Value: "4", Path: "/B"},
		&http.Cookie{Name: "e", Value: "5", Path: "/A"},
		&http.Cookie{Name: "f", Value: "6", Path: "/B"},
	})
	if jar.allNames() != "a;b;c;d;e;f" {
		t.Errorf("Initial. Have %s", jar.allNames())
	}

	// retrieve from path B: should update LastAccess on "B-cookies"
	time.Sleep(2 * time.Millisecond)
	jar.Cookies(uB)
	time.Sleep(2 * time.Millisecond)

	// add 3 more cookies
	jar.SetCookies(u, []*http.Cookie{
		&http.Cookie{Name: "g", Value: "7"},
		&http.Cookie{Name: "h", Value: "8"},
		&http.Cookie{Name: "i", Value: "9"},
	})
	// should kick out all A-cookies
	if jar.allNames() != "b;d;f;g;h;i" {
		t.Errorf("After. Have %s", jar.allNames())
	}

}

func TestGob(t *testing.T) {
	// set up some cookies
	now := time.Now()
	session := Cookie{"a", "1", "example.com", "/", false, false,
		time.Time{}, false, now, now}
	expired := Cookie{"b", "2", "", "/", false, false,
		now.Add(-2 * time.Minute), false, now, now}
	persistent1 := Cookie{"c", "3", "domain.xyz", "/foo", true, false,
		now.Add(60 * time.Minute), false, now, now}
	persistent2 := Cookie{"d", "4", "google.com", "/", false, false,
		now.Add(100 * time.Millisecond), false, now, now}

	// artificially put them into jar
	jar := Jar{}
	jar.cookies = []Cookie{session, expired, persistent1, persistent2}

	// gob encode and re-decode jar
	gob, err := jar.GobEncode()
	if err != nil {
		t.Errorf("Unexpected error: %s", err.Error())
	}
	err = jar.GobDecode(gob)
	if err != nil {
		t.Errorf("Unexpected error: %s", err.Error())
	}

	// encoding should have dropped expired and session cookie
	if len(jar.cookies) != 2 || jar.cookies[0].Name != "c" || jar.cookies[1].Name != "d" {
		cs := ""
		for _, c := range jar.cookies {
			cs += c.Name + "=" + c.Value + "; "
		}
		t.Errorf("Expected 2 cookies, got %d: %s", len(jar.cookies), cs)
	}

	// this should expire persistent2 in this later decoding
	time.Sleep(101 * time.Millisecond)
	err = jar.GobDecode(gob)
	if err != nil {
		t.Errorf("Unexpected error: %s", err.Error())
	}
	if len(jar.cookies) != 1 || jar.cookies[0].Name != "c" {
		// decoding should drop the now expired persistent2
		cs := ""
		for _, c := range jar.cookies {
			cs += c.Name + "=" + c.Value + "; "
		}
		t.Errorf("Expected one (c=3), got %d: %s", len(jar.cookies), cs)
	}

	if !reflect.DeepEqual(persistent1, jar.cookies[0]) {
		t.Errorf("Expected %v\ngot %v", persistent1, jar.cookies[0])
	}
}
