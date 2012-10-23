// Copyright 2012 Volker Dobler. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cookiejar

// Tests for the exported methods of Jar.

import (
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"testing"
	"time"
)

// -------------------------------------------------------------------------
// Helper functions and methods to simplify testing

// list yields the (non-expired) cookies of jar in a simple
// and deterministic format like "name1=value1 name2=value2":
// sorted alphabetical.
func (jar *Jar) list() string {
	all := jar.All()
	elements := make([]string, len(all))
	for i, cookie := range all {
		elements[i] = cookie.Name + "=" + cookie.Value
	}
	sort.Strings(elements)
	return strings.Join(elements, " ")
}

// difference compares recieved to expected (both in the above
// simple format) and returns any found differences in human
// readable format.
func difference(recieved, expected string) string {
	got := list2map(recieved)
	want := list2map(expected)

	excess := ""
	for k, _ := range got {
		if _, ok := want[k]; !ok {
			excess += " " + k
		}
	}
	if excess != "" {
		excess = "Excess:" + excess + "; "
	}

	missing := ""
	for k, _ := range want {
		if _, ok := got[k]; !ok {
			missing += " " + k
		}
	}
	if missing != "" {
		missing = "Missing:" + missing
	}

	return excess + missing
}

func list2map(list string) map[string]struct{} {
	m := make(map[string]struct{})
	for _, c := range strings.Fields(list) {
		m[c] = struct{}{}
	}
	return m
}

// stringRep transforms a http.Cookie slice to our
// "a=1 c=3" format for cookie checking.
func stringRep(cookies []*http.Cookie) string {
	s := ""
	for i, c := range cookies {
		if i > 0 {
			s += " "
		}
		s += c.Name + "=" + c.Value
	}
	return s
}

// parseCookie turns s (format of Set-Cookie header) into a http.Cookie.
func parseCookie(s string) *http.Cookie {
	cookies := (&http.Response{Header: http.Header{"Set-Cookie": {s}}}).Cookies()
	if len(cookies) != 1 {
		panic(fmt.Sprintf("Wrong cookie line %q: %#v", s, cookies))
	}
	return cookies[0]
}

// expiresIn creates an expires attribute delta seconds from now.
func expiresIn(delta int) string {
	t := time.Now().Add(time.Duration(delta) * time.Second)
	return "expires=" + t.Format(time.RFC1123)
}

// parse s to an URL and panic on error
func URL(s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil || u.Scheme == "" || u.Host == "" {
		panic(fmt.Sprintf("Unable to parse URL %s.", s))
	}
	return u
}

func TestTestHelpers(t *testing.T) {
	if difference("a=1 b=2 c=3", "c=3 a=1 b=2") != "" {
		t.Errorf("difference not order invariant")
	}

	jar := NewJar(false)
	jar.Add([]Cookie{
		Cookie{Name: "a", Value: "1"},
		Cookie{Name: "b", Value: "2"},
		Cookie{Name: "c", Value: "3"}})

	diff := difference(jar.list(), "b=2 c=3 d=4")
	if diff != "Excess: a=1; Missing: d=4" {
		t.Errorf("Got diff=%q", diff)
	}
}

// -------------------------------------------------------------------------
// jarTest: test SetCookies and Cookies methods

// jarTest encapsulatest the following actions on a jar:
//   1.  Perform SetCookies() with fromURL and the cookies from setCookies.
//   2.  Check that the content of the jar matches content.
//   3.  For each query in test: Check that Cookies() with toURL yields the
//       cookies in expected.
type jarTest struct {
	description string   // the description of what this test is supposed to test
	fromURL     string   // the full URL of the request to which Set-Cookie headers where recieved
	setCookies  []string // all the cookies recieved from fromURL in simplyfied form (see above)
	content     string   // the whole content of the jar
	tests       []query  // several testhat to expect, again as a cookie header line
}

// query contains one test of the cookies returned to Cookies().
type query struct {
	toURL    string // the URL in the Cookies() call
	expected string // the expected list of cookies (order matters)
}

// run performs the actions and test of test on jar.
func (test jarTest) run(t *testing.T, jar *Jar) {
	u := URL(test.fromURL)

	// populate jar with cookies
	setcookies := make([]*http.Cookie, len(test.setCookies))
	for i, cs := range test.setCookies {
		setcookies[i] = parseCookie(cs)
	}
	jar.SetCookies(u, setcookies)

	// make sure jar content matches our expectations
	if jar.list() != test.content {
		t.Errorf("Test %q: Wrong content.\nWant %q, got %q.",
			test.description, test.content, jar.list())
	}

	// test different calls to Cookies()
	for i, query := range test.tests {
		u := URL(query.toURL)
		cookies := jar.Cookies(u)
		recieved := stringRep(cookies)
		if recieved != query.expected {
			diff := difference(recieved, query.expected)
			if diff == "" {
				t.Errorf("Test %q, #%d: Wrong sorting.\nWant %q, got %q.",
					test.description, i, query.expected, recieved)
			} else {
				t.Errorf("Test %q, #%d: Wrong cookies.\nWant %q, got %q."+
					"\n Difference: %s",
					test.description, i, query.expected, recieved,
					diff)
			}
		}
	}
}

// -------------------------------------------------------------------------
// Basic test on Jar.

// basicJarTest contains test for the basic features of a cookie jar.
var basicJarTests = []jarTest{
	{"Retrieval of a plain cookie.",
		"http://www.host.test/",
		[]string{"A=a"},
		"A=a",
		[]query{
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
	{"HttpOnly is a noop as our jar is http only.",
		"http://www.host.test/",
		[]string{"A=a; httponly"},
		"A=a",
		[]query{
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
	{"Secure cookies are not returned to http.",
		"http://www.host.test/",
		[]string{"A=a; secure"},
		"A=a",
		[]query{
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
	{"HttpOnly is a noop for secure cookies too.",
		"http://www.host.test/",
		[]string{"A=a; secure; httponly"},
		"A=a",
		[]query{
			{"http://www.host.test", ""},
			{"http://www.host.test/", ""},
			{"http://www.host.test/some/path", ""},
			{"https://www.host.test", "A=a"},
			{"https://www.host.test/", "A=a"},
			{"https://www.host.test/some/path", "A=a"},
			{"ftp://www.host.test", ""},
			{"ftps://www.host.test", ""},
			{"ftp://www.host.test/", ""},
			{"ftp://www.host.test/some/path", ""},
			{"http://www.other.org", ""},
			{"http://sibling.host.test", ""},
			{"http://deep.www.host.test", ""},
		},
	},
	{"Cookie with explicit path.",
		"http://www.host.test/",
		[]string{"A=a; path=/some/path"},
		"A=a",
		[]query{
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
	{"Cookie with implicit path, variant a: path is directoy.",
		"http://www.host.test/some/path/",
		[]string{"A=a"},
		"A=a",
		[]query{
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
	{"Cookie with implicit path, variant b:: path is not directory",
		"http://www.host.test/some/path/index.html",
		[]string{"A=a"},
		"A=a",
		[]query{
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
	{"Cookie with implicit path, version c: no path in url at all.",
		"http://www.host.test",
		[]string{"A=a"},
		"A=a",
		[]query{
			{"http://www.host.test", "A=a"},
			{"http://www.host.test/", "A=a"},
			{"http://www.host.test/some/path", "A=a"},
		},
	},
	{"Returned cookies are sorted by path length.",
		"http://www.host.test/",
		[]string{
			"A=a; path=/foo/bar",
			"B=b; path=/foo/bar/baz/qux",
			"C=c; path=/foo/bar/baz",
			"D=d; path=/foo"},
		"A=a B=b C=c D=d",
		[]query{
			{"http://www.host.test/foo/bar/baz/qux", "B=b C=c A=a D=d"},
			{"http://www.host.test/foo/bar/baz/", "C=c A=a D=d"},
			{"http://www.host.test/foo/bar", "A=a D=d"},
		},
	},
	{"Returned cookies are sorted by creation time if path lengths are the same.",
		"http://www.host.test/",
		[]string{
			"A=a; path=/foo/bar",
			"X=x; path=/foo/bar",
			"Y=y; path=/foo/bar/baz/qux",
			"B=b; path=/foo/bar/baz/qux",
			"C=c; path=/foo/bar/baz",
			"W=w; path=/foo/bar/baz",
			"Z=z; path=/foo",
			"D=d; path=/foo"},
		"A=a B=b C=c D=d W=w X=x Y=y Z=z",
		[]query{
			{"http://www.host.test/foo/bar/baz/qux", "Y=y B=b C=c W=w A=a X=x Z=z D=d"},
			{"http://www.host.test/foo/bar/baz/", "C=c W=w A=a X=x Z=z D=d"},
			{"http://www.host.test/foo/bar", "A=a X=x Z=z D=d"},
		},
	},
	{"Several cookies with the same name but different paths and/or domain are sorted on path length and creation time",
		"http://www.test.org/",
		[]string{"A=1; path=/",
			"A=2; path=/path",
			"A=3; path=/quux",
			"A=4; path=/path/foo",
			"A=5; domain=.test.org; path=/path",
			"A=6; domain=.test.org; path=/quux",
			"A=7; domain=.test.org; path=/path/foo",
		},
		"A=1 A=2 A=3 A=4 A=5 A=6 A=7",
		[]query{
			{"http://www.test.org/path", "A=2 A=5 A=1"},
			{"http://www.test.org/path/foo", "A=4 A=7 A=2 A=5 A=1"},
		},
	},
}

func TestBasicFeatures(t *testing.T) {
	for _, test := range basicJarTests {
		jar := NewJar(false)
		test.run(t, jar)
	}
	for _, test := range basicJarTests {
		jar := NewJar(true)
		test.run(t, jar)
	}
}

var updateAndDeleteTests = []jarTest{
	{"Set some initial cookies",
		"http://www.example.com",
		[]string{"a=1", "b=2; secure", "c=3; httponly", "d=4; secure; httponly"},
		"a=1 b=2 c=3 d=4",
		[]query{
			{"http://www.example.com", "a=1 c=3"},
			{"https://www.example.com", "a=1 b=2 c=3 d=4"},
		},
	},
	{"We can update all of them to new value via http",
		"http://www.example.com",
		[]string{"a=w", "b=x; secure", "c=y; httponly", "d=z; secure; httponly"},
		"a=w b=x c=y d=z",
		[]query{
			{"http://www.example.com", "a=w c=y"},
			{"https://www.example.com", "a=w b=x c=y d=z"},
		},
	},
	{"We can clear a Secure flag from a http request",
		"http://www.example.com/",
		[]string{"b=xx", "d=zz; httponly"},
		"a=w b=xx c=y d=zz",
		[]query{{"http://www.example.com", "a=w b=xx c=y d=zz"}},
	},
	{"We can delete all of them",
		"http://www.example.com/",
		[]string{"a=1; max-Age=-1", //  delete via MaxAge
			"b=2; " + expiresIn(-10),             // delete via Expires
			"c=2; max-age=-1; " + expiresIn(-10), // delete via both
			"d=4; max-age=-1; " + expiresIn(10)}, // maxAge takes precedence
		"",
		[]query{{"http://www.example.com", ""}},
	},
}

func TestUpdateAndDelete(t *testing.T) {
	jar := NewJar(false)
	for _, test := range updateAndDeleteTests {
		test.run(t, jar)
	}
	jar = NewJar(true)
	for _, test := range updateAndDeleteTests {
		test.run(t, jar)
	}
}

var cookieDeletionTests = []jarTest{
	{"TestCookieDeletion: Fill jar part 1.",
		"http://www.host.test",
		[]string{
			"A=1",
			"A=2; path=/foo",
			"A=3; domain=.host.test",
			"A=4; path=/foo; domain=.host.test"},
		"A=1 A=2 A=3 A=4",
		[]query{{"http://www.host.test/foo", "A=2 A=4 A=1 A=3"}},
	},
	{"TestCookieDeletion: Fill jar part 2.",
		"http://www.google.com",
		[]string{
			"A=6",
			"A=7; path=/foo",
			"A=8; domain=.google.com",
			"A=9; path=/foo; domain=.google.com"},
		"A=1 A=2 A=3 A=4 A=6 A=7 A=8 A=9",
		[]query{
			{"http://www.host.test/foo", "A=2 A=4 A=1 A=3"},
			{"http://www.google.com/foo", "A=7 A=9 A=6 A=8"},
		},
	},
	{"TestCookieDeletion: Delete A7",
		"http://www.google.com",
		[]string{"A=; path=/foo; max-age=-1"},
		"A=1 A=2 A=3 A=4 A=6 A=8 A=9",
		[]query{
			{"http://www.host.test/foo", "A=2 A=4 A=1 A=3"},
			{"http://www.google.com/foo", "A=9 A=6 A=8"},
		},
	},
	{"TestCookieDeletion: Delete A4",
		"http://www.host.test",
		[]string{"A=; path=/foo; domain=host.test; max-age=-1"},
		"A=1 A=2 A=3 A=6 A=8 A=9",
		[]query{
			{"http://www.host.test/foo", "A=2 A=1 A=3"},
			{"http://www.google.com/foo", "A=9 A=6 A=8"},
		},
	},
	{"TestCookieDeletion: Delete A6",
		"http://www.google.com",
		[]string{"A=; max-age=-1"},
		"A=1 A=2 A=3 A=8 A=9",
		[]query{
			{"http://www.host.test/foo", "A=2 A=1 A=3"},
			{"http://www.google.com/foo", "A=9 A=8"},
		},
	},
	{"TestCookieDeletion: Delete A3",
		"http://www.host.test",
		[]string{"A=; domain=host.test; max-age=-1"},
		"A=1 A=2 A=8 A=9",
		[]query{
			{"http://www.host.test/foo", "A=2 A=1"},
			{"http://www.google.com/foo", "A=9 A=8"},
		},
	},
	{"TestCookieDeletion: no cross-domain delete",
		"http://www.host.test",
		[]string{"A=; domain=google.com; max-age=-1", "A=; path=/foo; domain=google.com; max-age=-1"},
		"A=1 A=2 A=8 A=9",
		[]query{
			{"http://www.host.test/foo", "A=2 A=1"},
			{"http://www.google.com/foo", "A=9 A=8"},
		},
	},
	{"TestCookieDeletion: Delete A8 and A9",
		"http://www.google.com",
		[]string{"A=; domain=google.com; max-age=-1", "A=; path=/foo; domain=google.com; max-age=-1"},
		"A=1 A=2",
		[]query{
			{"http://www.host.test/foo", "A=2 A=1"},
			{"http://www.google.com/foo", ""},
		},
	},
}

func TestCookieDeletion(t *testing.T) {
	jar := NewJar(false)
	for _, test := range cookieDeletionTests {
		test.run(t, jar)
	}
	jar = NewJar(true)
	for _, test := range cookieDeletionTests {
		test.run(t, jar)
	}
}

func TestMaxBytesPerCookie(t *testing.T) {
	jar := NewJar(false)
	jarTest{"Fill jar", "http://www.host.test",
		[]string{"a=1", "longcookiename=2"},
		"a=1 longcookiename=2",
		[]query{{"http://www.host.test", "a=1 longcookiename=2"}},
	}.run(t, jar)
	jar.MaxBytesPerCookie = 8
	jarTest{"Too big cookies", "http://www.host.test",
		[]string{"b=3", "verylongcookiename=4", "c=verylongvalue"},
		"a=1 b=3 longcookiename=2",
		[]query{{"http://www.host.test", "a=1 longcookiename=2 b=3"}},
	}.run(t, jar)
}

func TestHostCookieOnIP(t *testing.T) {
	jar := NewJar(false)
	jarTest{"Dissallow host cookie on IP", "http://127.0.0.1",
		[]string{"a=1; domain=127.0.0.1"},
		"",
		[]query{{"http://127.0.0.1", ""}},
	}.run(t, jar)
	jar.HostCookieOnIP = true
	jarTest{"Allow host cookie on IP", "http://127.0.0.1",
		[]string{"b=2; domain=127.0.0.1"},
		"b=2",
		[]query{
			{"http://127.0.0.1", "b=2"},
			// The following cannot happen but does test the
			// expected behaviour of beeing a host cookie.
			{"http://www.127.0.0.1", ""},
		},
	}.run(t, jar)
	f := jar.content.(*flat)
	if (*f)[0].HostOnly != true {
		t.Errorf("Not a host cookie.")
	}
}

func TestDomainCookiesOnPublicSuffixes(t *testing.T) {
	jar := NewJar(false)
	jarTest{"Dissallow PS", "http://www.bbc.co.uk",
		[]string{"a=1", "b=2; domain=co.uk"},
		"a=1",
		[]query{{"http://www.bbc.co.uk", "a=1"}},
	}.run(t, jar)
	jar.DomainCookiesOnPublicSuffixes = true
	jarTest{"Allow PS", "http://www.bbc.co.uk",
		[]string{"c=3; domain=co.uk"},
		"a=1 c=3",
		[]query{{"http://www.bbc.co.uk", "a=1 c=3"}},
	}.run(t, jar)
}

func TestExpiration(t *testing.T) {
	for _, b := range []bool{true, false} {
		jar := NewJar(b)
		jarTest{
			"Fill jar",
			"http://www.host.test",
			[]string{
				"a=1",
				"b=2; max-age=1",
				"c=3; " + expiresIn(1),
				"d=4; max-age=100",
			},
			"a=1 b=2 c=3 d=4",
			[]query{{"http://www.host.test", "a=1 b=2 c=3 d=4"}},
		}.run(t, jar)
		time.Sleep(1005 * time.Millisecond)

		jarTest{
			"Check jar",
			"http://www.host.test",
			[]string{},
			"a=1 d=4",
			[]query{{"http://www.host.test", "a=1 d=4"}},
		}.run(t, jar)

		// make sure the expired cookies get reused
		jarTest{
			"Adding two more",
			"http://www.host.test",
			[]string{"e=5", "f=6"},
			"a=1 d=4 e=5 f=6",
			[]query{{"http://www.host.test", "a=1 d=4 e=5 f=6"}},
		}.run(t, jar)
		if f, ok := jar.content.(*flat); ok {
			if len(*f) != 4 {
				t.Errorf("Strange jar size %d", len(*f))
			}
		} else {
			// TODO: test it here too?
		}
	}
}

// -------------------------------------------------------------------------
// Test derived from chromiums cookie_store_unittest.h.
// See http://src.chromium.org/viewvc/chrome/trunk/src/net/cookies/cookie_store_unittest.h?revision=159685&content-type=text/plain
// Some of these tests (e.g. DomainWithTrailingDotTest) are in a bad condition
// (aka buggy), so not all have been ported.

func TestChromiumDomainTest(t *testing.T) {
	for _, b := range []bool{true, false} {
		jar := NewJar(b)
		wwwGoogleIzzle := URL("http://www.google.izzle")
		fooWwwGoogleIzzle := URL("http://foo.www.google.izzle")
		aIzzle := URL("http://a.izzle")
		barWwwGoogleIzzle := URL("http://bar.www.google.izzle")

		jar.SetCookies(wwwGoogleIzzle, []*http.Cookie{parseCookie("A=B")})
		if got := stringRep(jar.Cookies(wwwGoogleIzzle)); got != "A=B" {
			t.Errorf("Got " + got)
		}

		jar.SetCookies(wwwGoogleIzzle, []*http.Cookie{parseCookie("C=D; domain=.google.izzle")})
		if got := stringRep(jar.Cookies(wwwGoogleIzzle)); got != "A=B C=D" {
			t.Errorf("Got " + got)
		}

		// verify A is a host cokkie and not accessible from subdomain
		if got := stringRep(jar.Cookies(fooWwwGoogleIzzle)); got != "C=D" {
			t.Errorf("Got " + got)
		}

		// verify domain cookies are found on proper domain
		jar.SetCookies(wwwGoogleIzzle, []*http.Cookie{parseCookie("E=F; domain=.www.google.izzle")})
		if got := stringRep(jar.Cookies(wwwGoogleIzzle)); got != "A=B C=D E=F" {
			t.Errorf("Got " + got)
		}

		// leading dots in domain attributes are optional
		jar.SetCookies(wwwGoogleIzzle, []*http.Cookie{parseCookie("G=H; domain=www.google.izzle")})
		if got := stringRep(jar.Cookies(wwwGoogleIzzle)); got != "A=B C=D E=F G=H" {
			t.Errorf("Got " + got)
		}

		// verify domain enforcement works (this one is bogus if public
		// suffixes are used: .izzle is considered a public suffix and
		// the domain cookie is silently rejected.)
		jar.SetCookies(wwwGoogleIzzle, []*http.Cookie{parseCookie("I=J; domain=.izzle")})
		if got := stringRep(jar.Cookies(aIzzle)); got != "" {
			t.Errorf("Got " + got)
		}
		jar.SetCookies(wwwGoogleIzzle, []*http.Cookie{parseCookie("K=L; domain=.bar.www.google.izzle")})
		if got := stringRep(jar.Cookies(barWwwGoogleIzzle)); got != "C=D E=F G=H" {
			t.Errorf("Got " + got)
		}
		if got := stringRep(jar.Cookies(wwwGoogleIzzle)); got != "A=B C=D E=F G=H" {
			t.Errorf("Got " + got)
		}
	}
}

// tests which can be done with the help of jarTest
var chromiumTests = []jarTest{
	{"DomainWithTrailingDotTest: Trailing dots in domain attributes are illegal",
		"http://www.google.com/",
		[]string{"a=1; domain=.www.google.com.", "b=2; domain=.www.google.com.."},
		"",
		[]query{
			{"http://www.google.com", ""},
		},
	},
	{"ValidSubdomainTest part 1: domain cookies on higer level domains are not" +
		"visible on lower level domains",
		"http://a.b.c.d.com",
		[]string{
			"a=1; domain=.a.b.c.d.com",
			"b=2; domain=.b.c.d.com",
			"c=3; domain=.c.d.com",
			"d=4; domain=.d.com"},
		"a=1 b=2 c=3 d=4",
		[]query{
			{"http://a.b.c.d.com", "a=1 b=2 c=3 d=4"},
			{"http://b.c.d.com", "b=2 c=3 d=4"},
			{"http://c.d.com", "c=3 d=4"},
			{"http://d.com", "d=4"},
		},
	},
	{"ValidSubdomainTest part 2: 'same' cookie on several sub-domains",
		"http://a.b.c.d.com",
		[]string{
			"a=1; domain=.a.b.c.d.com",
			"b=2; domain=.b.c.d.com",
			"c=3; domain=.c.d.com",
			"d=4; domain=.d.com",
			"X=bcd; domain=.b.c.d.com",
			"X=cd; domain=.c.d.com"},
		"X=bcd X=cd a=1 b=2 c=3 d=4",
		[]query{
			{"http://b.c.d.com", "b=2 c=3 d=4 X=bcd X=cd"},
			{"http://c.d.com", "c=3 d=4 X=cd"},
		},
	},
	{"InvalidDomainTest 1: ignore cookies whose domain attribute does not match originatin domain",
		"http://foo.bar.com",
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
		"", // jar is empty
		[]query{{"http://foo.bar.com", ""}},
	},
	{"InvalidDomainTest 2: special case with same domain and registry",
		"http://foo.com.com",
		[]string{"a=1; domain=.foo.com.com.com"},
		"",
		[]query{{"http://foo.bar.com", ""}},
	},
	{"DomainWithoutLeadingDotTest 1: Leading dot is optional for domain cookies",
		"http://manage.hosted.filefront.com",
		[]string{"a=1; domain=filefront.com"},
		"a=1",
		[]query{{"http://www.filefront.com", "a=1"}},
	},
	{"DomainWithoutLeadingDotTest 2: still domain cookie, even if domain and " +
		"domain attribute match exactly",
		"http://www.google.com",
		[]string{"a=1; domain=www.google.com"},
		"a=1",
		[]query{
			{"http://www.google.com", "a=1"},
			{"http://sub.www.google.com", "a=1"},
			{"http://something-else.com", ""},
		},
	},
	{"CaseInsensitiveDomainTest",
		"http://www.google.com",
		[]string{"a=1; domain=.GOOGLE.COM", "b=2; domain=.www.gOOgLE.coM"},
		"a=1 b=2",
		[]query{{"http://www.google.com", "a=1 b=2"}},
	},
	{"TestIpAddress 1: allow host cookies on IP address",
		"http://1.2.3.4/foo",
		[]string{"a=1; path=/"},
		"a=1",
		[]query{{"http://1.2.3.4/foo", "a=1"}},
	},
	{"TestIpAddress 2: disallow domain cookies on IP address",
		"http://1.2.3.4/foo",
		[]string{"a=1; domain=.1.2.3.4", "b=2; domain=.3.4"},
		"",
		[]query{{"http://1.2.3.4/foo", ""}},
	},
	{"TestIpAddress 3: really disallow domain cookies on IP address (even if IE&FF allow this case)",
		"http://1.2.3.4/foo",
		[]string{"a=1; domain=1.2.3.4"},
		"",
		[]query{{"http://1.2.3.4/foo", ""}},
	},
	{"TestNonDottedAndTLD 1: allow on com but only as host cookie",
		"http://com/",
		[]string{"a=1", "b=2; domain=.com", "c=3; domain=com"},
		"a=1",
		[]query{
			{"http://com/", "a=1"},
			{"http://no-cookies.com/", ""},
			{"http://.com/", ""},
		},
	},
	{"TestNonDottedAndTLD 2: treat com. same as com",
		"http://com./index.html",
		[]string{"a=1"},
		"a=1",
		[]query{
			{"http://com./index.html", "a=1"},
			{"http://no-cookies.com./index.html", ""},
		},
	},
	{"TestNonDottedAndTLD 3: cannot set host cookie from subdomain",
		"http://a.b",
		[]string{"a=1; domain=.b", "b=2; domain=b"},
		"",
		[]query{{"http://bar.foo", ""}},
	},
	{"TestNonDottedAndTLD 4: same as above but for known TLD (com)",
		"http://google.com",
		[]string{"a=1; domain=.com", "b=2; domain=com"},
		"",
		[]query{{"http://google.com", ""}},
	},
	{"TestNonDottedAndTLD 5: cannot set on TLD which is dotted",
		"http://google.co.uk",
		[]string{"a=1; domain=.co.uk", "b=2; domain=.uk"},
		"",
		[]query{
			{"http://google.co.uk", ""},
			{"http://else.co.com", ""},
			{"http://else.uk", ""},
		},
	},
	{"TestNonDottedAndTLD 6: intranet URLs may set host cookies only",
		"http://b",
		[]string{"a=1", "b=2; domain=.b", "c=3; domain=b"},
		"a=1",
		[]query{{"http://b", "a=1"}},
	},
	{"TestHostEndsWithDot: this seemes to be disallowed by RFC6265 even if browsers do other",
		"http://www.google.com",
		[]string{"a=1", "b=2; domain=.www.google.com."},
		"a=1",
		[]query{{"http://www.google.com", "a=1"}},
	},
	{"PathTest",
		"http://www.google.izzle",
		[]string{"a=1; path=/wee"},
		"a=1",
		[]query{
			{"http://www.google.izzle/wee", "a=1"},
			{"http://www.google.izzle/wee/", "a=1"},
			{"http://www.google.izzle/wee/war", "a=1"},
			{"http://www.google.izzle/wee/war/more/more", "a=1"},
			{"http://www.google.izzle/weehee", ""},
			{"http://www.google.izzle/", ""},
		},
	},
}

func TestChromiumTestcases(t *testing.T) {
	for _, test := range chromiumTests {
		jar := NewJar(false)
		test.run(t, jar)
		jar = NewJar(true)
		test.run(t, jar)
	}
}

var chromiumDeletionTests = []jarTest{
	{"TestCookieDeletion: Create session cookie a1",
		"http://www.google.com",
		[]string{"a=1"},
		"a=1",
		[]query{{"http://www.google.com", "a=1"}},
	},
	{"TestCookieDeletion: Delete sc a1 via MaxAge",
		"http://www.google.com",
		[]string{"a=1; max-age=-1"},
		"",
		[]query{{"http://www.google.com", ""}},
	},
	{"TestCookieDeletion: Create session cookie b2",
		"http://www.google.com",
		[]string{"b=2"},
		"b=2",
		[]query{{"http://www.google.com", "b=2"}},
	},
	{"TestCookieDeletion: Delete sc b2 via Expires",
		"http://www.google.com",
		[]string{"b=2; " + expiresIn(-10)},
		"",
		[]query{{"http://www.google.com", ""}},
	},
	{"TestCookieDeletion: Create persistent cookie c3",
		"http://www.google.com",
		[]string{"c=3; max-age=3600"},
		"c=3",
		[]query{{"http://www.google.com", "c=3"}},
	},
	{"TestCookieDeletion: Delete pc c3 via MaxAge",
		"http://www.google.com",
		[]string{"c=3; max-age=-1"},
		"",
		[]query{{"http://www.google.com", ""}},
	},
	{"TestCookieDeletion: Create persistant cookie d4",
		"http://www.google.com",
		[]string{"d=4; max-age=3600"},
		"d=4",
		[]query{{"http://www.google.com", "d=4"}},
	},
	{"TestCookieDeletion: Delete pc d4 via Expires",
		"http://www.google.com",
		[]string{"d=4; " + expiresIn(-10)},
		"",
		[]query{{"http://www.google.com", ""}},
	},
}

func TestChromiumCookieDeletion(t *testing.T) {
	jar := NewJar(true)
	for _, test := range chromiumDeletionTests {
		test.run(t, jar)
	}
	jar = NewJar(false)
	for _, test := range chromiumDeletionTests {
		test.run(t, jar)
	}
}

// -------------------------------------------------------------------------
// Test for the other exported methods

func TestAdd(t *testing.T) {
	for _, b := range []bool{true, false} {
		jar := NewJar(b)

		// a=1 gets added, b=2 is ignored as already expired, c=3 is a session cookie
		jar.Add([]Cookie{
			Cookie{
				Name: "a", Value: "1",
				Domain:   "www.host.test",
				Path:     "/foo",
				Expires:  time.Now().Add(time.Hour),
				Secure:   true,
				HostOnly: false,
			},
			Cookie{
				Name: "b", Value: "2",
				Domain:  "www.host.test",
				Path:    "/",
				Expires: time.Now().Add(-time.Minute), // expired
			},
			Cookie{
				Name: "c", Value: "3",
				Domain:  "www.google.com",
				Path:    "/",
				Expires: time.Time{}, // zero value = session cookie
			},
		})
		if jar.list() != "a=1 c=3" {
			t.Fatalf("Wrong content. Got %q", jar.list())
		}

		// adding d=4
		jar.Add([]Cookie{
			Cookie{
				Name: "d", Value: "4",
				Domain:   "www.somewhere.else",
				Path:     "/",
				Expires:  time.Now().Add(time.Hour),
				Secure:   true,
				HostOnly: false,
			},
		})
		if jar.list() != "a=1 c=3 d=4" {
			t.Fatalf("Wrong content. Got %q", jar.list())
		}

		// updating a
		jar.Add([]Cookie{
			Cookie{
				Name: "a", Value: "X",
				Domain:     "www.host.test",
				Path:       "/foo",
				Expires:    time.Now().Add(time.Hour),
				Secure:     false,
				HostOnly:   true,
				Created:    time.Now().Add(-time.Hour),
				LastAccess: time.Now().Add(-time.Minute),
			},
		})
		if jar.list() != "a=X c=3 d=4" {
			t.Fatalf("Wrong content. Got %q", jar.list())
		}
		u := URL("http://www.host.test/foo/bar") // not https!
		recieved := stringRep(jar.Cookies(u))
		if recieved != "a=X" {
			t.Errorf("Wrong cookies. Got %q", recieved)
		}
	}
}

func TestRemove(t *testing.T) {
	for _, b := range []bool{true, false} {
		jar := NewJar(b)

		jar.Add([]Cookie{
			Cookie{
				Name: "a", Value: "1",
				Domain: "www.host.test",
				Path:   "/foo",
			},
			Cookie{
				Name: "a", Value: "2",
				Domain: "www.host.test",
				Path:   "/bar",
			},
			Cookie{
				Name: "a", Value: "3",
				Domain: "www.google.com",
				Path:   "/bar",
			},
			Cookie{
				Name: "b", Value: "4",
				Domain: "www.google.com",
				Path:   "/bar",
			},
		})
		if jar.list() != "a=1 a=2 a=3 b=4" {
			t.Fatalf("Wrong content. Got %q", jar.list())
		}

		// cannot remove nonexisting cookie
		if jar.Remove("www.host.test", "/bar", "x") {
			t.Errorf("Could remove non-existing cookie x.")
		}

		// remove a=2
		if !jar.Remove("www.host.test", "/bar", "a") {
			t.Errorf("Could not remove cookie a=2.")
		}
		if jar.list() != "a=1 a=3 b=4" {
			t.Fatalf("Wrong content. Got %q", jar.list())
		}

		// remove a=3
		if !jar.Remove("www.google.com", "/bar", "a") {
			t.Errorf("Could not remove cookie a=3.")
		}
		if jar.list() != "a=1 b=4" {
			t.Fatalf("Wrong content. Got %q", jar.list())
		}
		// cannot remove an already removed cookie
		if jar.Remove("www.google.com", "/bar", "a") {
			t.Errorf("Could re-remove removed cookie a=3.")
		}
	}
}

// -------------------------------------------------------------------------
// Test update of LastAccess

func TestLastAccess(t *testing.T) {
	for _, b := range []bool{true, false} {
		f := "Mon, 02 Jan 2006 15:04:05.9999999 MST" // RFC1123 with sub-musec precision
		// helper to get the two cookies named "a" and "b" from a two-cookie jar.
		aAndB := func(jar *Jar) (cookieA, cookieB Cookie) {
			all := jar.All()
			if len(all) != 2 {
				panic(fmt.Sprintf("Expected two cookies. Got %", jar.list()))
			}
			// order in all is arbitary
			if all[0].Name == "a" {
				cookieA = all[0]
				cookieB = all[1]
			} else {
				cookieA = all[1]
				cookieB = all[0]
			}
			if cookieA.Name != "a" || cookieB.Name != "b" {
				panic(fmt.Sprintf("Expected cookies a and b. Got %", jar.list()))
			}
			return
		}

		jar := NewJar(b)
		t0 := time.Now().Add(-time.Second)

		jar.Add([]Cookie{
			Cookie{
				Name: "a", Value: "1",
				Domain:     "www.host.test",
				Path:       "/foo",
				LastAccess: t0,
			},
			Cookie{
				Name: "b", Value: "2",
				Domain:     "www.host.test",
				Path:       "/bar",
				LastAccess: t0,
			},
		})

		// access a=1
		u := URL("http://www.host.test/foo/bar")
		recieved := stringRep(jar.Cookies(u))
		if recieved != "a=1" {
			t.Errorf("Wrong cookies. Got %q", recieved)
		}

		// b=2 keeps last access time while a=1 gets its updated
		cookieA, cookieB := aAndB(jar)
		t1 := time.Now()
		if !cookieA.LastAccess.After(t0) && cookieA.LastAccess.Before(t1) {
			t.Errorf("Bad LastAccess %s. Should be between %s and %s",
				cookieA.LastAccess.Format(f), t0.Format(f), t1.Format(f))
		}
		if cookieB.LastAccess != t0 {
			t.Errorf("Bad LastAccess %s. Should equal %s",
				cookieB.LastAccess.Format(f), t0.Format(f))
		}

		// access b=2
		u = URL("http://www.host.test/bar")
		recieved = stringRep(jar.Cookies(u))
		if recieved != "b=2" {
			t.Errorf("Wrong cookies. Got %q", recieved)
		}

		// b=2 now fresher than a=1
		cookieA, cookieB = aAndB(jar)
		if !cookieB.LastAccess.After(cookieA.LastAccess) {
			t.Errorf("a: LastAccess=%s, b: LastAccess=%s",
				cookieA.LastAccess.Format(f), cookieB.LastAccess.Format(f))
		}
	}
}
