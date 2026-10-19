package dnspod

import "testing"

func seedDomainIDCache(t *testing.T, loginToken string, entries map[string]string) {
	t.Helper()
	provider := New(loginToken)
	scoped := make(map[string]string, len(entries))
	for zone, id := range entries {
		scoped[provider.domainIDCacheKey(zone)] = id
	}
	domainIDCacheMu.Lock()
	domainIDCache = scoped
	domainIDCacheMu.Unlock()
	t.Cleanup(func() {
		domainIDCacheMu.Lock()
		domainIDCache = map[string]string{}
		domainIDCacheMu.Unlock()
	})
}
