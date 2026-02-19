package lease_set

import (
	"testing"
)

func FuzzReadLeaseSet(f *testing.F) {
	// Seed corpus with various sizes
	f.Add([]byte{})
	f.Add(make([]byte, 100))
	f.Add(make([]byte, 387))
	f.Add(make([]byte, 500))
	f.Add(make([]byte, 1000))

	f.Fuzz(func(t *testing.T, input []byte) {
		// ReadLeaseSet should never panic
		ls, err := ReadLeaseSet(input)
		if err == nil {
			// If parsing succeeded, basic accessors should not panic
			_ = ls.Destination()
			_ = ls.LeaseCount()
			_ = ls.Leases()
			_ = ls.Signature()
			_, _ = ls.Bytes()
		}
	})
}
