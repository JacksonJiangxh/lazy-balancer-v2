package middleware

import "testing"

func resetLoginRateBuckets(t *testing.T) {
	t.Helper()
	loginRateBuckets.Lock()
	loginRateBuckets.entries = make(map[string]*loginRateBucket)
	loginRateBuckets.Unlock()
	t.Cleanup(func() {
		loginRateBuckets.Lock()
		loginRateBuckets.entries = make(map[string]*loginRateBucket)
		loginRateBuckets.Unlock()
	})
}
