package cookiejar

import (
	"fmt"
	"time"
)

var _ = fmt.Println

// FancyStorage implements Storage and keeps a FlatStorage for each
// "domain", e.g. for google.com and bbc.uk.co.  Wheter the "domain"
// is TLD plus one or the public suffix plus can be controlled.
type FancyStorage struct {
	tldPlusOne   bool // if true use TLD+1 instead of (effective TLD)+1
	maxPerDomain int
	maxTotal     int

	flat map[string]*FlatStorage
}

// NewFancyStorage creates a FancyStorage which uses either TLD + 1 
// (tldPlusOne==true) or the effective TLD + 1 (tldPlusOne==false) as 
// domain key.
func NewFancyStorage(tldPlusOne bool) *FancyStorage {
	return &FancyStorage{tldPlusOne: tldPlusOne, flat: make(map[string]*FlatStorage)}
}

// key looks up the tld+1 or etld+1 for the given domain
func (f *FancyStorage) key(domain string) (key string) {
	if f.tldPlusOne {
		// www.bbc.uk.co  -->  uk.co
		dot := false
		for n := len(domain) - 2; n > 0; n-- {
			if domain[n] == '.' {
				if dot {
					key = domain[n+1:]
					break
				}
				dot = true
			}
		}
		if key == "" {
			key = domain
		}
	} else {
		// www.bbc.uk.co  -->  bbc.uk.co
		key, _ = effectiveTldPlusOne(domain)
	}
	// fmt.Printf("using %q as key for domain %q\n", key, domain)
	return key
}

// Retrieve fetches the unsorted list of cookies to be sent
func (f *FancyStorage) Retrieve(host, path string, secure bool, now time.Time) []*Cookie {
	key := f.key(host)
	if fl, ok := f.flat[key]; ok {
		return fl.Retrieve(host, path, secure, now)
	}
	return nil
}

// Find looks up the cookie or returns a "new" cookie (which might be
// the reuse of an existing but expired or infrequently used cookie).
func (f *FancyStorage) Find(domain, path, name string, now time.Time) *Cookie {
	key := f.key(domain)
	fl, ok := f.flat[key]
	if !ok {
		fl = NewFlatStorage(5, f.maxPerDomain)
		f.flat[key] = fl
		// fmt.Printf("Allocate new flat for tld %s\n", key)
	}

	return fl.Find(domain, path, name, now)
}

// Delete the cookie <domain,path,name> from the storage.
func (f *FancyStorage) Delete(domain, path, name string) bool {
	key := f.key(domain)
	if fl, ok := f.flat[key]; ok {
		return fl.Delete(domain, path, name)
	}
	return false
}

func (f *FancyStorage) Empty() bool {
	for _, fl := range f.flat {
		if !fl.Empty() {
			return false
		}
	}
	return true
}

func (f *FancyStorage) RemoveExpired(now time.Time) (removed int) {
	for _, flat := range f.flat {
		removed += flat.RemoveExpired(now)
	}
	return removed
}

type fancyloc struct {
	key string
	idx int
}

func (f *FancyStorage) Cleanup(total, perDomain int, now time.Time) (removed int) {
	cnt := 0 // number of cookies in jar

	// delegate perDomain limit to each flat storage
	for k, fl := range f.flat {
		removed += fl.Cleanup(perDomain, 0, now)
		if fl.Empty() {
			delete(f.flat, k)
		} else {
			cnt += len(fl.cookies)
		}
	}

	del := cnt - total // amount to delete
	if total <= 0 || del <= 0 {
		return removed // done
	}

	// deletion happens on least used from all
	// fmt.Printf("Fancy: deleting %d to to maxtotal\n", del)
	lu := newLeastUsed(del)
	for k, fl := range f.flat {
		for i, cookie := range fl.cookies {
			lu.insert(cookie, fancyloc{key: k, idx: i})
		}
	}
	for _, cookie := range lu.elements() {
		loc := cookie.data.(fancyloc)
		f.flat[loc.key].remove(loc.idx)
	}

	return removed
}

func (f *FancyStorage) All(now time.Time) (cookies []*Cookie) {
	for _, flat := range f.flat {
		cookies = append(cookies, flat.All(now)...)
	}
	return cookies
}
