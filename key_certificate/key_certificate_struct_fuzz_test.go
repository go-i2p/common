package key_certificate

import (
	"testing"
)

// FuzzNewKeyCertificate exercises NewKeyCertificate with random binary input
// to verify it doesn't panic on malformed data.
func FuzzNewKeyCertificate(f *testing.F) {
	// Seed with valid key certificate data
	f.Add([]byte{0x05, 0x00, 0x04, 0x00, 0x07, 0x00, 0x04})
	f.Add([]byte{0x05, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00})
	// Seed with too-short data
	f.Add([]byte{0x05})
	f.Add([]byte{0x05, 0x00})
	// Seed with wrong certificate type
	f.Add([]byte{0x00, 0x00, 0x04, 0x00, 0x07, 0x00, 0x04})
	// Seed with excess data
	f.Add([]byte{0x05, 0x00, 0x04, 0x00, 0x07, 0x00, 0x04, 0xFF, 0xFF, 0xFF})

	f.Fuzz(func(t *testing.T, data []byte) {
		// Should never panic regardless of input
		keyCert, remainder, err := NewKeyCertificate(data)
		if err != nil {
			return
		}
		if keyCert == nil {
			t.Fatal("No error but keyCert is nil")
		}
		_ = keyCert.SigningPublicKeyType()
		_ = keyCert.PublicKeyType()
		_ = keyCert.SigningPublicKeySize()
		_ = keyCert.CryptoSize()
		_ = keyCert.SignatureSize()
		_ = remainder
	})
}
