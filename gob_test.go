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
	"testing"
	"time"
)

func TestGob(t *testing.T) {
	// set up some cookies
	now := time.Now()
	session := Cookie{"a", "1", "example.com", "/", time.Time{},
		false, false, false, now, now}
	expired := Cookie{"b", "2", "", "/", now.Add(-2 * time.Minute),
		false, false, false, now, now}
	persistent1 := Cookie{"c", "3", "domain.xyz", "/foo", now.Add(60 * time.Minute),
		true, false, false, now, now}
	persistent2 := Cookie{"d", "4", "google.com", "/", now.Add(100 * time.Millisecond),
		false, false, false, now, now}

	// artificially put them into jar
	jar := NewJar(JarConfig{FlatStorage: true})
	jar.storage.(*FlatStorage).cookies = []*Cookie{&session, &expired, &persistent1, &persistent2}

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
	if jar.allNames() != "c;d" {
		t.Errorf("Expected %q got %q", "c;d", jar.allNames())
	}

	// this should expire persistent2 in this later decoding
	time.Sleep(101 * time.Millisecond)
	err = jar.GobDecode(gob)
	if err != nil {
		t.Errorf("Unexpected error: %s", err.Error())
	}
	if jar.allNames() != "c" {
		t.Errorf("Expected %q got %q", "c", jar.allNames())
	}

}
