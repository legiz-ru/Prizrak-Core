package pingconfig

import (
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/singledo"
)

// connectivityTTL is how long one answer about the device's network holds:
// a burst of failed checks asks it once.
const connectivityTTL = 2 * time.Second

var connectivity = struct {
	sync.Mutex
	checks map[string]*singledo.Single[bool]
}{checks: map[string]*singledo.Single[bool]{}}

// Online says whether the device itself reaches the network, by probe of
// rawURL (a direct request, past every proxy). The answer is shared for
// connectivityTTL.
func Online(rawURL string, probe func() error) bool {
	connectivity.Lock()
	single, ok := connectivity.checks[rawURL]
	if !ok {
		single = singledo.NewSingle[bool](connectivityTTL)
		connectivity.checks[rawURL] = single
	}
	connectivity.Unlock()

	online, _, _ := single.Do(func() (bool, error) {
		return probe() == nil, nil
	})
	return online
}
