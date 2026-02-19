package encrypted_leaseset

import (
	"testing"
)

// ————————————————————————————————————————————————
// Fuzz tests for EncryptedLeaseSet parsing
// Source: encrypted_leaseset.go
// ————————————————————————————————————————————————

func FuzzReadEncryptedLeaseSet(f *testing.F) {
	// Seed 1: valid minimal EncryptedLeaseSet
	seed1 := buildMinimalELS(f)
	f.Add(seed1)

	// Seed 2: empty data
	f.Add([]byte{})

	// Seed 3: just under minimum length
	f.Add(make([]byte, ENCRYPTED_LEASESET_MIN_SIZE-1))

	// Seed 4: exactly minimum length with random data
	f.Add(make([]byte, ENCRYPTED_LEASESET_MIN_SIZE))

	// Seed 5: offline keys flag set in data with valid-looking structure
	seed5 := buildMinimalELSWithOfflineFlag(f)
	f.Add(seed5)

	f.Fuzz(func(t *testing.T, data []byte) {
		// Fuzz target: the parser must not panic regardless of input.
		// It may return an error, but must never crash.
		els, _, err := ReadEncryptedLeaseSet(data)
		if err != nil {
			return
		}

		// If parsing succeeded, validate internal consistency
		_ = els.Validate()

		// If parsing succeeded, serialization must not panic
		if serialized, sErr := els.Bytes(); sErr == nil {
			// Optional: round-trip check
			_, _, _ = ReadEncryptedLeaseSet(serialized)
		}
	})
}
