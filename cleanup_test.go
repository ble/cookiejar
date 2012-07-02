// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cookiejar

//
// Test of cleanup actions like removing expired cookies and
// excess cookies (in total or per domain).
//

import (
	// "fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"testing"
	"time"
)

// serialize all cookie names into one string after sorting names
// e.g. "a;b;x"
func (jar *Jar) allNames() string {
	names := make([]string, 0)
	now := time.Now()
	for _, c := range jar.All(now) {
		names = append(names, c.Name)
	}
	sort.Strings(names)
	return strings.Join(names, ";")
}

func TestMaxTotal(t *testing.T) {
	cfg := JarConfig{
		MaxCookiesPerDomain: 100,
		MaxCookiesTotal:     3, // at most 3 cookies in total in jar
		FlatStorage:         true,
	}
	jar := NewJar(cfg)
	testMaxTotal(jar, t, cfg.FlatStorage)

	cfg.FlatStorage = false
	jar = NewJar(cfg)
	testMaxTotal(jar, t, cfg.FlatStorage)
}

func testMaxTotal(jar *Jar, t *testing.T, flat bool) {
	u, _ := url.Parse("http://www.example.com")

	for i, tc := range []struct {
		cookies []*http.Cookie
		expect  string
	}{
		{
			[]*http.Cookie{
				&http.Cookie{Name: "a", Value: "1"},
				&http.Cookie{Name: "b", Value: "2"},
				&http.Cookie{Name: "c", Value: "3"},
			}, "a;b;c",
		},
		{
			[]*http.Cookie{&http.Cookie{Name: "d", Value: "4"}}, "b;c;d",
		},
		{
			[]*http.Cookie{
				&http.Cookie{Name: "e", Value: "5"},
				&http.Cookie{Name: "f", Value: "6"},
				&http.Cookie{Name: "g", Value: "7"},
				&http.Cookie{Name: "h", Value: "8"},
			}, "f;g;h",
		},
		{
			[]*http.Cookie{&http.Cookie{Name: "g", MaxAge: -1}}, "f;h",
		},
		{
			[]*http.Cookie{&http.Cookie{Name: "i", Value: "9"}}, "f;h;i",
		},
	} {
		jar.SetCookies(u, tc.cookies)
		if jar.allNames() != tc.expect {
			t.Errorf("%d (flat=%t). Have %q, Want %q", i, flat, jar.allNames(), tc.expect)
		}
	}

}

func TestMaxPerDomain(t *testing.T) {
	cfg := JarConfig{
		MaxCookiesPerDomain: 2,
		MaxCookiesTotal:     100,
		FlatStorage:         true,
	}
	jar := NewJar(cfg)
	testMaxPerDomain(jar, t, cfg.FlatStorage)
	cfg.FlatStorage = false
	jar = NewJar(cfg)
	testMaxPerDomain(jar, t, cfg.FlatStorage)
}

func testMaxPerDomain(jar *Jar, t *testing.T, flat bool) {
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
		t.Errorf("(flat=%t) Add to third.domain. Have %s", flat, jar.allNames())
	}

	// adding to second
	jar.SetCookies(u2, []*http.Cookie{&http.Cookie{Name: "h", Value: "8"}})
	if jar.allNames() != "a;b;d;f;g;h" {
		t.Errorf("(flat=%t) Add to second.domain. Have %s", flat, jar.allNames())
	}

	// adding to first
	jar.SetCookies(u1, []*http.Cookie{
		&http.Cookie{Name: "i", Value: "9", Domain: ""},
		&http.Cookie{Name: "j", Value: "10", Domain: "first.domain"},
	})
	if jar.allNames() != "d;f;g;h;i;j" {
		t.Errorf("(flat=%t) Add to first.domain. Have %s", flat, jar.allNames())
	}
}

func TestExpiresCleanup(t *testing.T) {
	cfg := JarConfig{
		FlatStorage: true,
	}
	jar := NewJar(cfg)
	testExpiresCleanup(jar, t)
	cfg.FlatStorage = true
	jar = NewJar(cfg)
	testExpiresCleanup(jar, t)
}

func testExpiresCleanup(jar *Jar, t *testing.T) {
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
	cfg := JarConfig{
		MaxCookiesPerDomain: 100,
		MaxCookiesTotal:     6,
		FlatStorage:         true,
	}
	jar := NewJar(cfg)
	testHonourLastAccesInCleanup(jar, t, cfg.FlatStorage)
	cfg.FlatStorage = false
	jar = NewJar(cfg)
	testHonourLastAccesInCleanup(jar, t, cfg.FlatStorage)
}

func testHonourLastAccesInCleanup(jar *Jar, t *testing.T, flat bool) {
	u, _ := url.Parse("http://www.example.com")
	uB, _ := url.Parse("http://www.example.com/B/too")

	// fill up some cookies with different path to allow different access
	jar.SetCookies(u, []*http.Cookie{
		&http.Cookie{Name: "a", Value: "1", Path: "/A"},
		&http.Cookie{Name: "b", Value: "2", Path: "/B"},
		&http.Cookie{Name: "c", Value: "3", Path: "/A"},
	})
	time.Sleep(time.Millisecond)
	jar.SetCookies(u, []*http.Cookie{
		&http.Cookie{Name: "d", Value: "4", Path: "/B"},
		&http.Cookie{Name: "e", Value: "5", Path: "/A"},
		&http.Cookie{Name: "f", Value: "6", Path: "/B"},
	})
	if jar.allNames() != "a;b;c;d;e;f" {
		t.Errorf("Initial (%t). Have %s", flat, jar.allNames())
	}

	// retrieve from path B: should update LastAccess on "/B-path-cookies"
	time.Sleep(time.Millisecond)
	jar.Cookies(uB)
	time.Sleep(time.Millisecond)

	// adding 3 more cookies should remove the oldest ("/A-path-cookies")
	jar.SetCookies(u, []*http.Cookie{
		&http.Cookie{Name: "g", Value: "7"},
		&http.Cookie{Name: "h", Value: "8"},
		&http.Cookie{Name: "i", Value: "9"},
	})
	if jar.allNames() != "b;d;f;g;h;i" {
		t.Errorf("After (%t). Have %s Want b;d;f;g;h;i", flat, jar.allNames())
	}

}

/************
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
***************/
