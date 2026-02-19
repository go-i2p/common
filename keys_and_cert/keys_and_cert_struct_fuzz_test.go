package keys_and_cert

import (
	"testing"
)

// ============================================================================
// Fuzz test for ReadKeysAndCert
// ============================================================================

func FuzzReadKeysAndCert(f *testing.F) {
	// Seed with valid ElGamal+Ed25519 data
	seed := make([]byte, KEYS_AND_CERT_DATA_SIZE)
	seed = append(seed, []byte{0x05, 0x00, 0x04, 0x00, 0x07, 0x00, 0x00}...)
	f.Add(seed)

	// Seed with NULL cert
	null := make([]byte, KEYS_AND_CERT_DATA_SIZE+3)
	f.Add(null)

	// Seed with short data
	f.Add([]byte{0x00, 0x01, 0x02})

	// Seed with X25519+Ed25519
	x25519Data := make([]byte, KEYS_AND_CERT_DATA_SIZE)
	x25519Data = append(x25519Data, []byte{0x05, 0x00, 0x04, 0x00, 0x07, 0x00, 0x04}...)
	f.Add(x25519Data)

	f.Fuzz(func(t *testing.T, input []byte) {
		// Should never panic, regardless of input
		kac, _, err := ReadKeysAndCert(input)
		if err == nil && kac != nil {
			// If parsing succeeded, Bytes() should not panic
			_, _ = kac.Bytes()
		}
	})
}
