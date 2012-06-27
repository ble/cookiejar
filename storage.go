package cookiejar

import (
	"encoding/gob"
	"time"
)

// UpdateAction is the return value of Storage's Update method.
type UpdateAction int

const (
	InvalidCookie updateAction = iota // cookies was rejected
	CreateCookie                      // new cookie was added
	UpdateCookie                      // existing cookie was updated
	DeleteCookie                      // existing cookie was deleted
	NoSuchCookie                      // requested the deletion of a non-existing cookie
)

// Storage is the onterface of a low-level cookie store.
// Cookies in the storage are identified as <domain,path,name>-tripples. 
// The Storage is supposed to do its own houskeeping but the calling site
// is responsible for any locking, preparation of data and defaults
// an updating of stuff like LastAccess in a cookie.
type Storage interface {
	// Find looks up an existing cookie.  It creates a new cookies
	// if the requested cookie is not jet in the storage.
	// A new/fresh cookie has an empty name while an existing cookie
	// has a non-empty name.
	Find(domain, path, name string, now time.Time) *Cookie

	// Delete the cookie <domain,path,name> from the storage and returns
	// whether a cookie was deleted or not.
	Delete(domain, path, name string) bool

	// Retrieve fetches the unsorted list of cookies to be sent.
	Retrieve(host, path string, secure bool, now time.Time) []*Cookie

	// RemoveExpired scans for expired cookies and removes them
	// from the storage.  The number of removed cookies is returned.
	RemoveExpired(now time.Time) int

	// Cleanup sanitizes the storage.  It enforces several limits:
	//   total:     total number of stored cookies;  least used ones
	//              are deleted if excess cookies have to be removed
	//   perDomain: limits the number of cookies per domain/etld+1
	// A value <= 0 indicates unlimited.
	// The number of removed cookies is returned.
	Cleanup(total, perDomain int, now time.Time) int

	// Empty checks if no valid (i.e. non-expired) cookie is stored.
	Empty() bool

	// All exposes all stored and non-expired cookies.
	All(now time.Time) []*Cookie

	gob.GobEncoder // allows serialization of the content
	gob.GobDecoder // allows the deserialization of the content
}
