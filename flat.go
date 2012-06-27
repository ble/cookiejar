package cookiejar

import (
	"bytes"
	"encoding/gob"
	"time"
)

// FlatStorage implements a simple storage for cookies.  The actual storage
// is an unsorted arry of pointers to the stored cookies which is searched
// linearely any time we look for a cookie
type FlatStorage struct {
	MaxCookies int // maximal number of cookies to keep. <=0 indicates unlimited.

	cookies []*Cookie // flat list of cookies here
}

// NewFlatStorage creates a FlatStorage with the given capacity of initial.
func NewFlatStorage(initial int) *FlatStorage {
	return &FlatStorage{cookies: make([]*Cookie, 0, initial)}
}

// GobEncode implements the gob.GobEncoder interface.
func (f *FlatStorage) GobEncode() ([]byte, error) {
	var buf bytes.Buffer
	encoder := gob.NewEncoder(&buf)
	encoder.Encode(f.cookies)
	return buf.Bytes(), nil
}

// GobDecode implements the gob.GobDecoder interface.
// Only nonexpired cookies will be added to the jar.
func (f *FlatStorage) GobDecode(buf []byte) error {
	// Read everything into data)
	data := make([]*Cookie, 0)
	bb := bytes.NewBuffer(buf)
	decoder := gob.NewDecoder(bb)
	err := decoder.Decode(&data)
	if err != nil {
		return err
	}

	f.cookies = make([]*Cookie, 0)
	now := time.Now()
	for _, cookie := range data {
		if cookie.IsExpired(now) {
			continue
		}
		f.cookies = append(f.cookies, cookie)
	}
	return nil
}

// Retrieve fetches the unsorted list of cookies to be sent
func (f *FlatStorage) Retrieve(host, path string, secure bool, now time.Time) []*Cookie {
	selection := make([]*Cookie, 0)
	for _, cookie := range f.cookies {
		if cookie.empty() { // TODO: no empties in FlatStorage
			continue
		}
		if cookie.shouldSend(host, path, secure, now) {
			selection = append(selection, cookie)
		}
	}
	return selection
}

// Find looks up the cookie or returns a "new" cookie (which might be
// the reuse of an existing but expired or infrequently used cookie).
func (f *FlatStorage) Find(domain, path, name string, now time.Time) *Cookie {
	expiredIdx, oldestIdx := -1, -1
	leastUsed := farFuture
	for i, cookie := range f.cookies {
		// see if the cookie is there
		if domain == cookie.Domain &&
			path == cookie.Path &&
			name == cookie.Name {
			return cookie
		}

		// track expired and least used ones
		if expiredIdx != -1 {
			if cookie.IsExpired(now) {
				expiredIdx = i
			} else if cookie.LastAccess.Before(leastUsed) {
				oldestIdx = i
				leastUsed = cookie.LastAccess
			}
		}
	}

	// reuse expired cookie
	if expiredIdx != -1 {
		f.cookies[expiredIdx].Name = "" // clear name to indicate "new" cookie
		return f.cookies[expiredIdx]
	}

	// reuse least used cookie if domain storage is full
	if f.MaxCookies > 0 && len(f.cookies) >= f.MaxCookies {
		// reuse least used
		f.cookies[oldestIdx].Name = "" // clear name to indicate "new"
		return f.cookies[oldestIdx]
	}

	// a genuine new cookie
	cookie := &Cookie{}
	f.cookies = append(f.cookies, cookie)
	return cookie
}

// Delete the cookie <domain,path,name> from the storage.
func (f *FlatStorage) Delete(domain, path, name string) bool {
	n := len(f.cookies)
	if n == 0 {
		return false
	}
	for i := range f.cookies {
		if domain == f.cookies[i].Domain &&
			path == f.cookies[i].Path &&
			name == f.cookies[i].Name {
			if i < n-1 {
				f.cookies[i] = f.cookies[n-1]
			}
			f.cookies = f.cookies[:n-1]
			return true
		}
	}
	return false
}

// remove cookie at index i
func (f *FlatStorage) remove(i int) {
	n := len(f.cookies) - 1
	if i < n {
		f.cookies[i] = f.cookies[n]
	}
	f.cookies = f.cookies[:n]
}

// index of c in f.cookies
func (f *FlatStorage) index(c *Cookie) int {
	for i, cookie := range f.cookies {
		if cookie == c {
			return i
		}
	}
	panic("Not found")
}

func (f *FlatStorage) RemoveExpired(now time.Time) (removed int) {
	for i := 0; i < len(f.cookies); i++ {
		if f.cookies[i].IsExpired(now) {
			f.remove(i)
			removed++
		}
	}
	return removed
}

func (f *FlatStorage) Empty() bool {
	now := time.Now()
	for _, cookie := range f.cookies {
		if !cookie.IsExpired(now) {
			return false
		}
	}
	return true
}

func (f *FlatStorage) Cleanup(total, perDomain int, now time.Time) (removed int) {
	removed = f.RemoveExpired(now)

	if perDomain > 0 {
		removed += f.cleanupPerDomain(perDomain)
	}

	if total > 0 && len(f.cookies) > total {
		del := len(f.cookies) - total
		lu := leastUsed{n: del, cookies: make([]*Cookie, 0, del)}
		for _, cookie := range f.cookies {
			lu.insert(cookie)
		}
		for _, cookie := range lu.cookies {
			f.remove(f.index(cookie))
		}

		removed += del
	}

	return removed
}

func (f *FlatStorage) cleanupPerDomain(max int) (removed int) {
	// TODO: might require code...
	return 0
}

func (f *FlatStorage) All(now time.Time) (cookies []*Cookie) {
	f.RemoveExpired(now)
	return f.cookies
}

func aaaaa() {
	jar := Jar{}
	jar.Storage = NewFlatStorage(5)
}
