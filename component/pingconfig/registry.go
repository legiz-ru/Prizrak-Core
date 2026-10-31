package pingconfig

import (
	"sync"
	"sync/atomic"
)

// Registry maps group urls to their profiles: one profile per url.
type Registry struct {
	profiles map[string]*Profile
}

func NewRegistry() *Registry {
	return &Registry{profiles: map[string]*Profile{}}
}

// Add keys p by its url. The first profile of a url stays: Add returns it,
// and whether p differs from it.
func (r *Registry) Add(p *Profile) (kept *Profile, conflict bool) {
	if old, ok := r.profiles[p.URL]; ok {
		return old, !old.Same(p)
	}
	r.profiles[p.URL] = p
	return p, false
}

// Lookup returns the profile of url, or nil.
func (r *Registry) Lookup(url string) *Profile {
	if r == nil {
		return nil
	}
	return r.profiles[url]
}

func (r *Registry) Len() int {
	if r == nil {
		return 0
	}
	return len(r.profiles)
}

var active atomic.Pointer[Registry]

// SetActive makes r the registry of the running config, replacing the
// previous one whole. nil clears it.
func SetActive(r *Registry) {
	active.Store(r)
}

// Lookup returns the running config's profile of url, or nil.
func Lookup(url string) *Profile {
	return active.Load().Lookup(url)
}

type claimKey struct {
	node any
	url  string
}

var claims = struct {
	sync.Mutex
	owner map[claimKey]any
}{owner: map[claimKey]any{}}

// Claim makes owner the one scheduler that checks node at url, unless
// another owner has it: a node shared by several providers or groups is
// checked once per slot, not once per provider.
func Claim(owner, node any, url string) bool {
	claims.Lock()
	defer claims.Unlock()
	key := claimKey{node: node, url: url}
	if cur, ok := claims.owner[key]; ok {
		return cur == owner
	}
	claims.owner[key] = owner
	return true
}

// Retain releases owner's claims at url on nodes not in keep.
func Retain(owner any, url string, keep map[any]struct{}) {
	claims.Lock()
	defer claims.Unlock()
	for key, cur := range claims.owner {
		if cur != owner || key.url != url {
			continue
		}
		if _, ok := keep[key.node]; !ok {
			delete(claims.owner, key)
		}
	}
}

// Release drops every claim of owner.
func Release(owner any) {
	claims.Lock()
	defer claims.Unlock()
	for key, cur := range claims.owner {
		if cur == owner {
			delete(claims.owner, key)
		}
	}
}
