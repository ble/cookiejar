// Copyright 2012 Volker Dobler. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cookiejar

import (
	"fmt"
)

var _ = fmt.Printf

// -------------------------------------------------------------------------
// Storage

// storage is the interface of a cookie monster.
type storage interface {
	retrieve(https bool, host, path string) []*Cookie
	find(domain, path, name string) *Cookie
	delete(domain, path, name string) bool
}

// -------------------------------------------------------------------------
// Flat

// flat implements a simple storage for cookies.  The actual storage
// is an unsorted arry of pointers to the stored cookies which is searched
// linearely any time we look for a cookie
type flat []*Cookie

// retrieve fetches the unsorted list of cookies to be sent
func (f *flat) retrieve(https bool, host, path string) []*Cookie {
	selection := make([]*Cookie, 0)
	expired := 0
	for _, cookie := range *f {
		if cookie.Expired() {
			expired++
		} else {
			if cookie.shouldSend(https, host, path) {
				selection = append(selection, cookie)
			}
		}
	}

	if expired > 10 && expired > len(*f)/5 {
		f.cleanup(expired)
	}

	return selection
}

// find looks up the cookie <domain,path,name> or returns a "new" cookie
// (which might be the reuse of an existing but expired one).
func (f *flat) find(domain, path, name string) *Cookie {
	expiredIdx := -1
	for i, cookie := range *f {
		// see if the cookie is there
		if domain == cookie.Domain &&
			path == cookie.Path &&
			name == cookie.Name {
			return cookie
		}

		// track expired
		if expiredIdx == -1 {
			if cookie.Expired() {
				expiredIdx = i
			}
		}
	}

	// reuse expired cookie
	if expiredIdx != -1 {
		(*f)[expiredIdx].Name = "" // clear name to indicate "new" cookie
		return (*f)[expiredIdx]
	}

	// a genuine new cookie
	cookie := &Cookie{}
	*f = append(*f, cookie)
	return cookie
}

// delete the cookie <domain,path,name> from the storage. Returns true if the
// cookie was present in the jar.
func (f *flat) delete(domain, path, name string) bool {
	n := len(*f)
	if n == 0 {
		return false
	}
	for i := range *f {
		if domain == (*f)[i].Domain &&
			path == (*f)[i].Path &&
			name == (*f)[i].Name {
			if i < n-1 {
				(*f)[i] = (*f)[n-1]
			}
			(*f) = (*f)[:n-1]
			return true
		}
	}
	return false
}

// cleanup removes expired cookies from f
func (f *flat) cleanup(num int) {
	// corner cases
	if num == 0 {
		return
	}
	if num == len(*f) {
		*f = (*f)[:0]
		return
	}

	i, j, n := 0, len(*f), 0

	for n < num {
		for i < j && !(*f)[i].Expired() { // find next expired
			i++
		}
		if i == j-1 {
			j--
			break
		}
		j--
		for j > i && (*f)[j].Expired() { // find non expired from back
			j--
			n++
		}

		if i == j || n == num {
			break
		}
		(*f)[i] = (*f)[j] // overwrite expired with non-expired
		i++
		n++
	}

	*f = (*f)[0:j] // reslice
}

// -------------------------------------------------------------------------
// Boxed

// boxed is a storage grouped by domain.
type boxed map[string]*flat

// return the proper flat for host or nil if non present
func (b *boxed) flat(host string) *flat {
	box := EffectiveTLDPlusOne(host)
	if box == "" {
		box = host
	}
	return (*b)[box]
}

// retrieve fetches the unsorted list of cookies to be sent
func (b *boxed) retrieve(https bool, host, path string) []*Cookie {
	if flat := b.flat(host); flat != nil {
		return flat.retrieve(https, host, path)
	}
	return nil
}

// find looks up the cookie <domain,path,name> or returns a "new" cookie
// (which might be the reuse of an existing but expired one).
func (b *boxed) find(domain, path, name string) *Cookie {
	if flat := b.flat(domain); flat != nil {
		return flat.find(domain, path, name)
	}

	f := make(flat, 1)
	box := EffectiveTLDPlusOne(domain)
	if box == "" {
		box = domain
	}
	f[0] = &Cookie{}
	(*b)[box] = &f
	return f[0]
}

// delete the cookie <domain,path,name> from the storage. Returns true if the
// cookie was present in the jar.
func (b *boxed) delete(domain, path, name string) bool {
	if flat := b.flat(domain); flat != nil {
		return flat.delete(domain, path, name)
	}
	return false
}
