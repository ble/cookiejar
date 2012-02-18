// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cookiejar

// Some utility functions which operate on URLs or parts if an URL.

import (
	"net"
	"net/url"
	"strings"
)

// Host returns the (canonical) host from an URL u.
// If the 
func host(u *url.URL) (string, error) {
	host := strings.ToLower(u.Host)
	if strings.Index(host, ":") < 0 {
		return host, nil
	}

	// else strip port
	host, _, err := net.SplitHostPort(host)
	if err != nil {
		return "", err
	}

	// TODO: handle canonicalisation if really needed

	return host, nil
}

// isSecure checks for https scheme
func isSecure(u *url.URL) bool {
	return strings.ToLower(u.Scheme) == "https"
}

// isHTTP checks for http(s) schemes
func isHTTP(u *url.URL) bool {
	scheme := strings.ToLower(u.Scheme)
	return scheme == "http" || scheme == "https"
}

// check if host is formaly an IPv4 address
func isIP(host string) bool {
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return ip.String() == host
}

// return "directory" part of path from u with suitable default.
// See RFC 6265 section 5.1.4:
//    path in url  |  directory
//   --------------+------------ 
//    ""           |  "/"
//    "xy/z"       |  "/"
//    "/abc"       |  "/"
//    "/ab/xy/km"  |  "/ab/xy"
//    "/abc/"      |  "/abc"
// We strip a trailing "/" during storage to faciliate the test in pathMatch().
func defaultPath(u *url.URL) string {
	path := u.Path

	// the "" and "xy/z" case
	if len(path) == 0 || path[0] != '/' {
		return "/"
	}

	// path starts with / --> i!=-1
	i := strings.LastIndex(path, "/")
	if i == 0 {
		// the "/abc" case
		return "/"
	}

	// the "/ab/xy/km" and "/abc/" case
	return path[:i]
}
