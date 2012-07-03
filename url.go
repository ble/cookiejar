// Copyright 2012 Volker Dobler. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cookiejar

// Some utility functions which operate on URLs or parts if an URL
// and on domain names.

import (
	"net"
	"net/url"
	"strings"
	// "idn/punycode"
)

// dummy until real go-idn is used
type dummy bool

func (d dummy) ToASCII(host string) (string, error) { return host, nil }

var punycode dummy

// host returns the (canonical) host from an URL u.
// See RFC 6265 section 5.1.2
// TODO: idns are not handeled at all.
func host(u *url.URL) (host string, err error) {
	host = strings.ToLower(u.Host)
	if strings.HasSuffix(host, ".") {
		// treat all domain names the same: 
		// strip trailing dot from fully qualified domain names
		host = host[:len(host)-1]
	}
	if strings.Index(host, ":") != -1 {
		host, _, err = net.SplitHostPort(host)
		if err != nil {
			return "", err
		}
	}

	host, err = punycode.ToASCII(host)
	if err != nil {
		return "", err
	}

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
