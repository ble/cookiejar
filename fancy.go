package cookiejar

import (
	"bytes"
	"encoding/gob"
	"time"
)

// FancyStorage implements Storage and keeps a FlatStorage for each
// "domain", e.g. for google.com and bbc.uk.co.  Wheter the "domain"
// is TLD plus one or the public suffix plus can be controlled.
type FancyStorage struct {
	tldPlusOne          bool // if true use TLD+1 instead of (effective TLD)+1
	MaxCookiesPerDomain int
	MaxCookiesTotal     int

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
	} else {
		// www.bbc.uk.co  -->  bbc.uk.co
		_, _, key = publicsuffixRules.info(domain)
	}
	if key == "" {
		return domain
	}
	return key
}

// GobEncode implements the gob.GobEncoder interface.
func (f *FancyStorage) GobEncode() ([]byte, error) {
	var buf bytes.Buffer
	encoder := gob.NewEncoder(&buf)
	encoder.Encode(f.flat)
	return buf.Bytes(), nil
}

// GobDecode implements the gob.GobDecoder interface.
// Only nonexpired cookies will be added to the jar.
func (f *FancyStorage) GobDecode(buf []byte) error {
	bb := bytes.NewBuffer(buf)
	decoder := gob.NewDecoder(bb)
	err := decoder.Decode(&f.flat)
	if err != nil {
		return err
	}
	return nil
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
		fl = NewFlatStorage(5)
		f.flat[key] = fl
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

func (f *FancyStorage) Cleanup(total, perDomain int, now time.Time) (removed int) {
	for k, fl := range f.flat {
		removed += fl.Cleanup(perDomain, 0, now)
		if fl.Empty() {
			delete(f.flat, k)
		}
	}
	return removed
}

func (f *FancyStorage) All(now time.Time) (cookies []*Cookie) {
	for _, flat := range f.flat {
		cookies = append(flat.All(now))
	}
	return cookies
}

func aaaa() {
	jar := Jar{}
	jar.Storage = NewFancyStorage(true)
}
