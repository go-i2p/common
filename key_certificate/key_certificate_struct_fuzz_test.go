package key_certificate

import (
	"testing"

	"github.com/go-i2p/common/certificate"
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

// FuzzKeyCertificateFromCertificate exercises KeyCertificateFromCertificate
// with random certificate payloads to verify it never panics.
func FuzzKeyCertificateFromCertificate(f *testing.F) {
	f.Add([]byte{0x00, 0x07, 0x00, 0x04})                         // Ed25519/X25519
	f.Add([]byte{0x00, 0x00, 0x00, 0x00})                         // DSA/ElGamal
	f.Add([]byte{0x00})                                           // Too short
	f.Add([]byte{})                                               // Empty
	f.Add([]byte{0xFF, 0xFF, 0xFF, 0xFF})                         // Unknown types
	f.Add([]byte{0x00, 0x03, 0x00, 0x00, 0xDE, 0xAD, 0xBE, 0xEF}) // P521 with excess

	f.Fuzz(func(t *testing.T, payload []byte) {
		cert, err := certificate.NewCertificateWithType(certificate.CERT_KEY, payload)
		if err != nil {
			return
		}

		keyCert, err := KeyCertificateFromCertificate(cert)
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
		_, _ = keyCert.Data()
	})
}
