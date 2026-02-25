package router_identity

import (
	"testing"

	"github.com/go-i2p/common/key_certificate"
	"github.com/go-i2p/common/keys_and_cert"
	"github.com/stretchr/testify/assert"
)

// FuzzNewRouterIdentityFromKeysAndCert fuzzes the constructor via KeysAndCert
func FuzzNewRouterIdentityFromKeysAndCert(f *testing.F) {
	seed := buildRouterIdentityBytes(f,
		key_certificate.KEYCERT_SIGN_ED25519,
		key_certificate.KEYCERT_CRYPTO_X25519,
	)
	f.Add(seed)

	f.Fuzz(func(t *testing.T, data []byte) {
		kac, _, err := keys_and_cert.ReadKeysAndCert(data)
		if err != nil {
			return
		}
		ri, err := NewRouterIdentityFromKeysAndCert(kac)
		if err != nil {
			return
		}
		assert.True(t, ri.IsValid())
		assert.NotNil(t, ri.KeysAndCert)
	})
}

// FuzzNewRouterIdentityFromBytes fuzzes the byte parser
func FuzzNewRouterIdentityFromBytes(f *testing.F) {
	seed := buildRouterIdentityBytes(f,
		key_certificate.KEYCERT_SIGN_ED25519,
		key_certificate.KEYCERT_CRYPTO_X25519,
	)
	f.Add(seed)

	// DSA-SHA1/ElGamal seed (KEY certificate form)
	f.Add(createValidRouterIdentityBytes(f))

	// NULL certificate seed: exercises the non-KEY-cert parsing path.
	nullSeed := make([]byte, keys_and_cert.KEYS_AND_CERT_DATA_SIZE+3)
	nullSeed[keys_and_cert.KEYS_AND_CERT_DATA_SIZE] = 0x00 // CERT_NULL
	f.Add(nullSeed)

	f.Fuzz(func(t *testing.T, data []byte) {
		ri, _, err := NewRouterIdentityFromBytes(data)
		if err != nil {
			return
		}
		assert.True(t, ri.IsValid())
		assert.NotNil(t, ri.KeysAndCert)
	})
}

// FuzzReadRouterIdentity fuzzes the wire-format parser directly.
func FuzzReadRouterIdentity(f *testing.F) {
	// Valid Ed25519/X25519 seed
	seed := buildRouterIdentityBytes(f,
		key_certificate.KEYCERT_SIGN_ED25519,
		key_certificate.KEYCERT_CRYPTO_X25519,
	)
	f.Add(seed)

	// Valid DSA-SHA1/ElGamal seed (KEY certificate form)
	dsaSeed := createValidRouterIdentityBytes(f)
	f.Add(dsaSeed)

	// NULL certificate seed (387 bytes): 384 random key bytes + [0x00, 0x00, 0x00]
	// Exercises readKeysAndCertNonKeyCert / buildNullCertKeyCertificate path.
	nullSeed := make([]byte, keys_and_cert.KEYS_AND_CERT_DATA_SIZE+3)
	nullSeed[keys_and_cert.KEYS_AND_CERT_DATA_SIZE] = 0x00 // CERT_NULL
	// length bytes already zero (0x00, 0x00)
	f.Add(nullSeed)

	// Short data seed
	f.Add([]byte{0x00, 0x01, 0x02})

	// Empty seed
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		ri, _, err := ReadRouterIdentity(data)
		if err != nil {
			return
		}
		assert.NotNil(t, ri)
		assert.NotNil(t, ri.KeysAndCert)
		// Verify round-trip if parsing succeeded
		b, err := ri.Bytes()
		if err == nil && len(b) > 0 {
			ri2, _, err2 := ReadRouterIdentity(b)
			if err2 == nil {
				assert.True(t, ri.Equal(ri2), "round-trip must preserve equality")
			}
		}
	})
}
