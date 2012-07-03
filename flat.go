package cookiejar

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"time"
)

var _ = fmt.Printf

// FlatStorage implements a simple storage for cookies.  The actual storage
// is an unsorted arry of pointers to the stored cookies which is searched
// linearely any time we look for a cookie
type FlatStorage struct {
	maxCookies int       // maximal number of cookies to keep. <=0 indicates unlimited.
	cookies    []*Cookie // flat list of cookies here
}

// NewFlatStorage creates a FlatStorage with the given capacity of initial.
func NewFlatStorage(initial, max int) *FlatStorage {
	return &FlatStorage{
		maxCookies: max,
		cookies:    make([]*Cookie, 0, initial),
	}
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
		if expiredIdx == -1 {
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
	if f.maxCookies > 0 && len(f.cookies) >= f.maxCookies {
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
		// fmt.Printf("Flat: removed cookie %s\n", f.cookies[i].Name)
		f.cookies[i] = f.cookies[n]
	}
	f.cookies = f.cookies[:n]
}

// remove all these cookies from f.cookies which are in lu.
func (f *FlatStorage) removeLU(lu *leastUsed) {
	n := len(f.cookies)
	for i := range lu.elem {
		n--                        // index of effective last (not to be sliced away) element in f.cookies
		d := lu.elem[i].data.(int) // index of element in f.cookies to delete
		if d == n {                // delete effective last element is a noop: it's sliced away below
			continue
		}
		// replace elem to delete with effective last
		f.cookies[d] = f.cookies[n]

		// update rest if lu.elem as indices may change due to deletion
		for j := i + 1; j < len(lu.elem); j++ {
			k := lu.elem[j].data.(int)
			if k == n {
				k = d
			} else if k > d {
				k--
			}
			lu.elem[j].data = k
		}
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
	// fmt.Printf("Flat.Cleanup(%d, %d)\n", total, perDomain)
	removed = f.RemoveExpired(now)

	if perDomain > 0 {
		removed += f.cleanupPerDomain(perDomain)
	}

	if total > 0 && len(f.cookies) > total {
		del := len(f.cookies) - total
		lu := newLeastUsed(del)
		for i, cookie := range f.cookies {
			lu.insert(cookie, i)
		}
		f.removeLU(lu)
		removed += del
	}

	return removed
}

func (f *FlatStorage) cleanupPerDomain(max int) (removed int) {
	domain := func(s string) string { return s }

	// sort all cookies into domain-bins
	bins := make(map[string][]int)
	for i, c := range f.cookies {
		key := domain(c.Domain)
		bins[key] = append(bins[key], i)
	}

	// iterate over these domain bins
	for _, indices := range bins {
		del := len(indices) - max // number of cookies to delete
		if del <= 0 {
			continue
		}
		// fmt.Printf("domain %s requires %d cleanup\n", key, del)
		lu := newLeastUsed(del)
		for _, i := range indices {
			lu.insert(f.cookies[i], i)
		}
		f.removeLU(lu)
		removed += del

	}

	return removed
}

func (f *FlatStorage) All(now time.Time) (cookies []*Cookie) {
	f.RemoveExpired(now)
	return f.cookies
}
