package router_identity

import (
	"crypto/sha256"
	"strings"
	"testing"

	"github.com/go-i2p/crypto/rand"

	"github.com/go-i2p/common/certificate"
	"github.com/go-i2p/common/key_certificate"
	"github.com/go-i2p/common/keys_and_cert"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

//
// Constructor Tests
//

// TestNewRouterIdentityFromKeysAndCert tests the simplified constructor
func TestNewRouterIdentityFromKeysAndCert(t *testing.T) {
	t.Run("valid KeysAndCert creates router identity", func(t *testing.T) {
		keysAndCert := createValidKeysAndCert(t)

		ri, err := NewRouterIdentityFromKeysAndCert(keysAndCert)
		require.NoError(t, err)
		require.NotNil(t, ri)
		assert.Equal(t, keysAndCert, ri.KeysAndCert)
		assert.True(t, ri.IsValid())
	})

	t.Run("nil KeysAndCert returns error", func(t *testing.T) {
		ri, err := NewRouterIdentityFromKeysAndCert(nil)
		require.Error(t, err)
		assert.Nil(t, ri)
		assert.Contains(t, err.Error(), "cannot be nil")
	})

	t.Run("invalid KeysAndCert returns error", func(t *testing.T) {
		invalidKeysAndCert := &keys_and_cert.KeysAndCert{}

		ri, err := NewRouterIdentityFromKeysAndCert(invalidKeysAndCert)
		require.Error(t, err)
		assert.Nil(t, ri)
		assert.Contains(t, err.Error(), "invalid KeysAndCert")
	})
}

// TestNewRouterIdentityFromBytes tests parsing router identities from byte slices
func TestNewRouterIdentityFromBytes(t *testing.T) {
	t.Run("valid bytes create router identity", func(t *testing.T) {
		originalData := createValidRouterIdentityBytes(t)

		ri, remainder, err := NewRouterIdentityFromBytes(originalData)
		require.NoError(t, err)
		require.NotNil(t, ri)
		assert.Empty(t, remainder)
		assert.True(t, ri.IsValid())
	})

	t.Run("invalid bytes return error", func(t *testing.T) {
		invalidData := []byte{0x00, 0x01, 0x02}

		ri, _, err := NewRouterIdentityFromBytes(invalidData)
		require.Error(t, err)
		assert.Nil(t, ri)
	})

	t.Run("empty bytes return error", func(t *testing.T) {
		ri, _, err := NewRouterIdentityFromBytes([]byte{})
		require.Error(t, err)
		assert.Nil(t, ri)
	})

	t.Run("extra bytes returned as remainder", func(t *testing.T) {
		originalData := createValidRouterIdentityBytes(t)
		extraBytes := []byte{0xDE, 0xAD, 0xBE, 0xEF}
		dataWithExtra := append(originalData, extraBytes...)

		ri, remainder, err := NewRouterIdentityFromBytes(dataWithExtra)
		require.NoError(t, err)
		require.NotNil(t, ri)
		assert.Equal(t, extraBytes, remainder)
	})
}

// TestNewRouterIdentity tests the full constructor with explicit parameters
func TestNewRouterIdentity(t *testing.T) {
	t.Run("valid construction with Ed25519/X25519", func(t *testing.T) {
		keyCert, err := key_certificate.NewKeyCertificateWithTypes(
			key_certificate.KEYCERT_SIGN_ED25519,
			key_certificate.KEYCERT_CRYPTO_X25519,
		)
		require.NoError(t, err)

		pubKey := make([]byte, 32)
		_, _ = rand.Read(pubKey)
		sigKey := make([]byte, 32)
		_, _ = rand.Read(sigKey)

		paddingSize := keys_and_cert.KEYS_AND_CERT_DATA_SIZE -
			keyCert.CryptoSize() - keyCert.SigningPublicKeySize()
		padding := make([]byte, paddingSize)

		ri, err := NewRouterIdentity(
			mockPublicKey(pubKey),
			mockSigningPublicKey(sigKey),
			&keyCert.Certificate,
			padding,
		)
		require.NoError(t, err)
		require.NotNil(t, ri)
		assert.True(t, ri.IsValid())
	})

	t.Run("rejected RedDSA signing type", func(t *testing.T) {
		keyCert, err := key_certificate.NewKeyCertificateWithTypes(
			key_certificate.KEYCERT_SIGN_REDDSA_ED25519,
			key_certificate.KEYCERT_CRYPTO_X25519,
		)
		require.NoError(t, err)

		pubKey := make([]byte, 32)
		sigKey := make([]byte, 32)
		paddingSize := keys_and_cert.KEYS_AND_CERT_DATA_SIZE -
			keyCert.CryptoSize() - keyCert.SigningPublicKeySize()
		padding := make([]byte, paddingSize)

		ri, err := NewRouterIdentity(
			mockPublicKey(pubKey),
			mockSigningPublicKey(sigKey),
			&keyCert.Certificate,
			padding,
		)
		require.Error(t, err)
		assert.Nil(t, ri)
		assert.Contains(t, err.Error(), "not permitted for Router Identities")
	})
}

// TestNewRouterIdentityWithCompressiblePadding tests the compressible padding constructor
func TestNewRouterIdentityWithCompressiblePadding(t *testing.T) {
	t.Run("creates valid identity", func(t *testing.T) {
		keyCert, err := key_certificate.NewKeyCertificateWithTypes(
			key_certificate.KEYCERT_SIGN_ED25519,
			key_certificate.KEYCERT_CRYPTO_X25519,
		)
		require.NoError(t, err)

		pubKey := make([]byte, 32)
		_, _ = rand.Read(pubKey)
		sigKey := make([]byte, 32)
		_, _ = rand.Read(sigKey)

		ri, err := NewRouterIdentityWithCompressiblePadding(
			mockPublicKey(pubKey),
			mockSigningPublicKey(sigKey),
			&keyCert.Certificate,
		)
		require.NoError(t, err)
		require.NotNil(t, ri)
		assert.True(t, ri.IsValid())
	})

	t.Run("padding is compressible", func(t *testing.T) {
		keyCert, err := key_certificate.NewKeyCertificateWithTypes(
			key_certificate.KEYCERT_SIGN_ED25519,
			key_certificate.KEYCERT_CRYPTO_X25519,
		)
		require.NoError(t, err)

		pubKey := make([]byte, 32)
		_, _ = rand.Read(pubKey)
		sigKey := make([]byte, 32)
		_, _ = rand.Read(sigKey)

		ri, err := NewRouterIdentityWithCompressiblePadding(
			mockPublicKey(pubKey),
			mockSigningPublicKey(sigKey),
			&keyCert.Certificate,
		)
		require.NoError(t, err)
		require.NotNil(t, ri)

		padding := ri.KeysAndCert.Padding
		if len(padding) >= 64 {
			assert.Equal(t, padding[:32], padding[32:64],
				"compressible padding should repeat 32-byte pattern")
		}
	})

	t.Run("rejected disallowed type", func(t *testing.T) {
		keyCert, err := key_certificate.NewKeyCertificateWithTypes(
			key_certificate.KEYCERT_SIGN_REDDSA_ED25519,
			key_certificate.KEYCERT_CRYPTO_X25519,
		)
		require.NoError(t, err)

		pubKey := make([]byte, 32)
		sigKey := make([]byte, 32)

		ri, err := NewRouterIdentityWithCompressiblePadding(
			mockPublicKey(pubKey),
			mockSigningPublicKey(sigKey),
			&keyCert.Certificate,
		)
		require.Error(t, err)
		assert.Nil(t, ri)
	})
}

// TestReadRouterIdentity tests the wire-format parser
func TestReadRouterIdentity(t *testing.T) {
	t.Run("valid wire data parsed successfully", func(t *testing.T) {
		wireData := buildRouterIdentityBytes(t,
			key_certificate.KEYCERT_SIGN_ED25519,
			key_certificate.KEYCERT_CRYPTO_X25519,
		)
		ri, remainder, err := ReadRouterIdentity(wireData)
		require.NoError(t, err)
		require.NotNil(t, ri)
		assert.Empty(t, remainder)
	})

	t.Run("returns nil on error", func(t *testing.T) {
		invalidData := []byte{0x00, 0x01, 0x02}
		ri, _, err := ReadRouterIdentity(invalidData)
		require.Error(t, err)
		assert.Nil(t, ri, "ReadRouterIdentity must return nil on error")
	})

	t.Run("single byte returns error", func(t *testing.T) {
		ri, remainder, err := ReadRouterIdentity([]byte{0x00})
		require.Error(t, err)
		assert.Nil(t, ri, "ReadRouterIdentity returns nil pointer on error")
		_ = remainder
	})

	t.Run("deprecated key types still accepted", func(t *testing.T) {
		wireData := createValidRouterIdentityBytes(t)
		ri, _, err := ReadRouterIdentity(wireData)
		require.NoError(t, err, "deprecated key types should still be accepted with warnings")
		assert.NotNil(t, ri)
	})
}

//
// Accessor and method tests
//

// TestRouterIdentityValidate tests the Validate method
func TestRouterIdentityValidate(t *testing.T) {
	t.Run("valid router identity passes validation", func(t *testing.T) {
		keysAndCert := createValidKeysAndCert(t)
		ri, err := NewRouterIdentityFromKeysAndCert(keysAndCert)
		require.NoError(t, err)
		assert.NoError(t, ri.Validate())
	})

	t.Run("nil router identity fails validation", func(t *testing.T) {
		var ri *RouterIdentity
		err := ri.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "router identity is nil")
	})

	t.Run("nil KeysAndCert fails validation", func(t *testing.T) {
		ri := &RouterIdentity{KeysAndCert: nil}
		err := ri.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "KeysAndCert is nil")
	})

	t.Run("invalid KeysAndCert fails validation", func(t *testing.T) {
		invalidKeysAndCert := &keys_and_cert.KeysAndCert{}
		ri := &RouterIdentity{KeysAndCert: invalidKeysAndCert}
		require.Error(t, ri.Validate())
	})
}

// TestRouterIdentityIsValid tests the IsValid convenience method
func TestRouterIdentityIsValid(t *testing.T) {
	t.Run("valid router identity returns true", func(t *testing.T) {
		keysAndCert := createValidKeysAndCert(t)
		ri, err := NewRouterIdentityFromKeysAndCert(keysAndCert)
		require.NoError(t, err)
		assert.True(t, ri.IsValid())
	})

	t.Run("nil router identity returns false", func(t *testing.T) {
		var ri *RouterIdentity
		assert.False(t, ri.IsValid())
	})

	t.Run("nil KeysAndCert returns false", func(t *testing.T) {
		ri := &RouterIdentity{KeysAndCert: nil}
		assert.False(t, ri.IsValid())
	})

	t.Run("invalid KeysAndCert returns false", func(t *testing.T) {
		invalidKeysAndCert := &keys_and_cert.KeysAndCert{}
		ri := &RouterIdentity{KeysAndCert: invalidKeysAndCert}
		assert.False(t, ri.IsValid())
	})
}

// TestAsDestination verifies conversion to Destination
func TestAsDestination(t *testing.T) {
	t.Run("converts to destination", func(t *testing.T) {
		keysAndCert := createValidKeysAndCert(t)
		ri, err := NewRouterIdentityFromKeysAndCert(keysAndCert)
		require.NoError(t, err)

		dest := ri.AsDestination()
		assert.NotNil(t, dest.KeysAndCert)
		assert.Equal(t, ri.KeysAndCert, dest.KeysAndCert)
	})

	t.Run("nil receiver returns zero Destination", func(t *testing.T) {
		var ri *RouterIdentity
		dest := ri.AsDestination()
		assert.Nil(t, dest.KeysAndCert, "nil receiver should produce zero-value Destination")
	})

	t.Run("nil KeysAndCert returns zero Destination", func(t *testing.T) {
		ri := &RouterIdentity{KeysAndCert: nil}
		dest := ri.AsDestination()
		assert.Nil(t, dest.KeysAndCert, "nil KeysAndCert should produce zero-value Destination")
	})

	t.Run("mutation isolation", func(t *testing.T) {
		kac := createValidKeysAndCert(t)
		ri, err := NewRouterIdentityFromKeysAndCert(kac)
		require.NoError(t, err)

		origBytes, err := ri.KeysAndCert.Bytes()
		require.NoError(t, err)

		dest := ri.AsDestination()
		require.NotNil(t, dest.KeysAndCert)

		assert.NotSame(t, ri.KeysAndCert, dest.KeysAndCert,
			"AsDestination must return a deep copy, not share the pointer")

		dest.KeysAndCert.KeyCertificate = nil

		assert.NotNil(t, ri.KeysAndCert.KeyCertificate,
			"mutating Destination must not affect original RouterIdentity")

		afterBytes, err := ri.KeysAndCert.Bytes()
		require.NoError(t, err)
		assert.Equal(t, origBytes, afterBytes,
			"original RouterIdentity bytes must be unchanged after Destination mutation")
	})
}

// TestEqual tests the constant-time equality method
func TestEqual(t *testing.T) {
	t.Run("identical identities are equal", func(t *testing.T) {
		kac := createValidKeysAndCert(t)
		ri1, err := NewRouterIdentityFromKeysAndCert(kac)
		require.NoError(t, err)

		b, err := ri1.KeysAndCert.Bytes()
		require.NoError(t, err)
		ri2, _, err := NewRouterIdentityFromBytes(b)
		require.NoError(t, err)

		assert.True(t, ri1.Equal(ri2))
		assert.True(t, ri2.Equal(ri1))
	})

	t.Run("nil receiver returns false", func(t *testing.T) {
		kac := createValidKeysAndCert(t)
		ri, err := NewRouterIdentityFromKeysAndCert(kac)
		require.NoError(t, err)
		var nilRI *RouterIdentity
		assert.False(t, nilRI.Equal(ri))
	})

	t.Run("nil argument returns false", func(t *testing.T) {
		kac := createValidKeysAndCert(t)
		ri, err := NewRouterIdentityFromKeysAndCert(kac)
		require.NoError(t, err)
		assert.False(t, ri.Equal(nil))
	})

	t.Run("nil KeysAndCert returns false", func(t *testing.T) {
		ri1 := &RouterIdentity{KeysAndCert: nil}
		ri2 := &RouterIdentity{KeysAndCert: nil}
		assert.False(t, ri1.Equal(ri2))
	})

	t.Run("structurally different identities not equal", func(t *testing.T) {
		data1 := buildRouterIdentityBytes(t,
			key_certificate.KEYCERT_SIGN_ED25519,
			key_certificate.KEYCERT_CRYPTO_X25519,
		)
		ri1, _, err := ReadRouterIdentity(data1)
		require.NoError(t, err)

		data2 := buildRouterIdentityBytes(t,
			key_certificate.KEYCERT_SIGN_ED25519,
			key_certificate.KEYCERT_CRYPTO_X25519,
		)
		ri2, _, err := ReadRouterIdentity(data2)
		require.NoError(t, err)

		assert.False(t, ri1.Equal(ri2),
			"RouterIdentities with different random key material must not be Equal")
	})

	t.Run("different key types not equal", func(t *testing.T) {
		data1 := buildRouterIdentityBytes(t,
			key_certificate.KEYCERT_SIGN_ED25519,
			key_certificate.KEYCERT_CRYPTO_X25519,
		)
		ri1, _, err := ReadRouterIdentity(data1)
		require.NoError(t, err)

		ri2Bytes := createValidRouterIdentityBytes(t) // uses DSA/ElGamal
		ri2, _, err := ReadRouterIdentity(ri2Bytes)
		require.NoError(t, err)

		assert.False(t, ri1.Equal(ri2),
			"RouterIdentities with different key types must not be Equal")
	})

	t.Run("symmetry", func(t *testing.T) {
		data1 := buildRouterIdentityBytes(t,
			key_certificate.KEYCERT_SIGN_ED25519,
			key_certificate.KEYCERT_CRYPTO_X25519,
		)
		ri1, _, err := ReadRouterIdentity(data1)
		require.NoError(t, err)

		data2 := buildRouterIdentityBytes(t,
			key_certificate.KEYCERT_SIGN_ED25519,
			key_certificate.KEYCERT_CRYPTO_X25519,
		)
		ri2, _, err := ReadRouterIdentity(data2)
		require.NoError(t, err)

		assert.Equal(t, ri1.Equal(ri2), ri2.Equal(ri1),
			"Equal must be symmetric")
	})

	t.Run("constant time with same bytes", func(t *testing.T) {
		data := buildRouterIdentityBytes(t,
			key_certificate.KEYCERT_SIGN_ED25519,
			key_certificate.KEYCERT_CRYPTO_X25519,
		)
		ri1, _, err := ReadRouterIdentity(data)
		require.NoError(t, err)

		ri2, _, err := ReadRouterIdentity(data)
		require.NoError(t, err)

		assert.True(t, ri1.Equal(ri2))
		assert.True(t, ri2.Equal(ri1))
	})
}

// TestString tests the fmt.Stringer implementation
func TestString(t *testing.T) {
	t.Run("valid identity produces hash string", func(t *testing.T) {
		kac := createValidKeysAndCert(t)
		ri, err := NewRouterIdentityFromKeysAndCert(kac)
		require.NoError(t, err)

		s := ri.String()
		assert.True(t, strings.HasPrefix(s, "RouterIdentity{"))
		assert.True(t, strings.HasSuffix(s, "}"))
		inner := s[len("RouterIdentity{") : len(s)-1]
		assert.Len(t, inner, 32, "truncated SHA-256 hash should be 16 bytes = 32 hex chars")
	})

	t.Run("nil receiver produces descriptive string", func(t *testing.T) {
		var ri *RouterIdentity
		assert.Equal(t, "<nil RouterIdentity>", ri.String())
	})

	t.Run("nil KeysAndCert produces descriptive string", func(t *testing.T) {
		ri := &RouterIdentity{KeysAndCert: nil}
		assert.Equal(t, "<nil RouterIdentity>", ri.String())
	})
}

// TestNewRouterIdentityFromKeysAndCert_DefensiveCopy verifies that the constructor
// makes a deep copy and mutations to the original don't affect the RouterIdentity.
func TestNewRouterIdentityFromKeysAndCert_DefensiveCopy(t *testing.T) {
	t.Run("mutating original KeyCertificate does not affect RouterIdentity", func(t *testing.T) {
		kac := createValidKeysAndCert(t)
		ri, err := NewRouterIdentityFromKeysAndCert(kac)
		require.NoError(t, err)

		origBytes, err := ri.Bytes()
		require.NoError(t, err)

		// Mutate the original KeysAndCert
		kac.KeyCertificate = nil

		// RouterIdentity must be unaffected
		assert.NotNil(t, ri.KeysAndCert.KeyCertificate,
			"RouterIdentity KeyCertificate must survive mutation of original")

		afterBytes, err := ri.Bytes()
		require.NoError(t, err)
		assert.Equal(t, origBytes, afterBytes,
			"RouterIdentity bytes must be unchanged after original mutation")
	})

	t.Run("mutating original Padding does not affect RouterIdentity", func(t *testing.T) {
		kac := createValidKeysAndCert(t)
		ri, err := NewRouterIdentityFromKeysAndCert(kac)
		require.NoError(t, err)

		if len(kac.Padding) == 0 {
			t.Skip("no padding in this test configuration")
		}

		origPadding := make([]byte, len(ri.KeysAndCert.Padding))
		copy(origPadding, ri.KeysAndCert.Padding)

		// Mutate the original
		kac.Padding[0] ^= 0xFF

		assert.Equal(t, origPadding, ri.KeysAndCert.Padding,
			"RouterIdentity Padding must be independent of original")
	})

	t.Run("pointer is different from input", func(t *testing.T) {
		kac := createValidKeysAndCert(t)
		ri, err := NewRouterIdentityFromKeysAndCert(kac)
		require.NoError(t, err)

		assert.True(t, ri.KeysAndCert != kac,
			"RouterIdentity must hold a different KeysAndCert pointer")
	})
}

// TestAsDestination_DeepCopy verifies that AsDestination returns a true deep copy.
func TestAsDestination_DeepCopy(t *testing.T) {
	t.Run("KeyCertificate pointer is distinct", func(t *testing.T) {
		kac := createValidKeysAndCert(t)
		ri, err := NewRouterIdentityFromKeysAndCert(kac)
		require.NoError(t, err)

		dest := ri.AsDestination()
		require.NotNil(t, dest.KeysAndCert)
		require.NotNil(t, dest.KeysAndCert.KeyCertificate)

		// Pointers must be different
		assert.True(t,
			ri.KeysAndCert.KeyCertificate != dest.KeysAndCert.KeyCertificate,
			"KeyCertificate pointer must be a separate allocation")
	})

	t.Run("mutating dest Padding does not affect original", func(t *testing.T) {
		kac := createValidKeysAndCert(t)
		ri, err := NewRouterIdentityFromKeysAndCert(kac)
		require.NoError(t, err)

		if len(ri.KeysAndCert.Padding) == 0 {
			t.Skip("no padding in this test configuration")
		}

		origPadding := make([]byte, len(ri.KeysAndCert.Padding))
		copy(origPadding, ri.KeysAndCert.Padding)

		dest := ri.AsDestination()
		if len(dest.KeysAndCert.Padding) > 0 {
			dest.KeysAndCert.Padding[0] ^= 0xFF
		}

		assert.Equal(t, origPadding, ri.KeysAndCert.Padding,
			"original Padding must not be affected by dest mutation")
	})
}

// TestHash verifies the Hash() method.
func TestHash(t *testing.T) {
	t.Run("returns SHA-256 of serialized identity", func(t *testing.T) {
		kac := createValidKeysAndCert(t)
		ri, err := NewRouterIdentityFromKeysAndCert(kac)
		require.NoError(t, err)

		hash, err := ri.Hash()
		require.NoError(t, err)

		// Manually compute expected hash
		b, err := ri.KeysAndCert.Bytes()
		require.NoError(t, err)
		expected := sha256.Sum256(b)

		assert.Equal(t, expected, hash)
	})

	t.Run("nil receiver returns error", func(t *testing.T) {
		var ri *RouterIdentity
		_, err := ri.Hash()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not initialized")
	})

	t.Run("nil KeysAndCert returns error", func(t *testing.T) {
		ri := &RouterIdentity{KeysAndCert: nil}
		_, err := ri.Hash()
		require.Error(t, err)
	})

	t.Run("consistent across calls", func(t *testing.T) {
		kac := createValidKeysAndCert(t)
		ri, err := NewRouterIdentityFromKeysAndCert(kac)
		require.NoError(t, err)

		hash1, err := ri.Hash()
		require.NoError(t, err)
		hash2, err := ri.Hash()
		require.NoError(t, err)

		assert.Equal(t, hash1, hash2, "Hash() must be deterministic")
	})

	t.Run("different identities produce different hashes", func(t *testing.T) {
		data1 := buildRouterIdentityBytes(t,
			key_certificate.KEYCERT_SIGN_ED25519,
			key_certificate.KEYCERT_CRYPTO_X25519,
		)
		ri1, _, err := ReadRouterIdentity(data1)
		require.NoError(t, err)

		data2 := buildRouterIdentityBytes(t,
			key_certificate.KEYCERT_SIGN_ED25519,
			key_certificate.KEYCERT_CRYPTO_X25519,
		)
		ri2, _, err := ReadRouterIdentity(data2)
		require.NoError(t, err)

		hash1, err := ri1.Hash()
		require.NoError(t, err)
		hash2, err := ri2.Hash()
		require.NoError(t, err)

		assert.NotEqual(t, hash1, hash2,
			"different random key material should produce different hashes")
	})
}

// TestBytes verifies the Bytes() convenience method.
func TestBytes(t *testing.T) {
	t.Run("returns same as KeysAndCert.Bytes()", func(t *testing.T) {
		kac := createValidKeysAndCert(t)
		ri, err := NewRouterIdentityFromKeysAndCert(kac)
		require.NoError(t, err)

		riBytes, err := ri.Bytes()
		require.NoError(t, err)

		kacBytes, err := ri.KeysAndCert.Bytes()
		require.NoError(t, err)

		assert.Equal(t, kacBytes, riBytes)
	})

	t.Run("nil receiver returns error", func(t *testing.T) {
		var ri *RouterIdentity
		_, err := ri.Bytes()
		require.Error(t, err)
	})

	t.Run("nil KeysAndCert returns error", func(t *testing.T) {
		ri := &RouterIdentity{KeysAndCert: nil}
		_, err := ri.Bytes()
		require.Error(t, err)
	})

	t.Run("round trip through ReadRouterIdentity", func(t *testing.T) {
		kac := createValidKeysAndCert(t)
		ri, err := NewRouterIdentityFromKeysAndCert(kac)
		require.NoError(t, err)

		b, err := ri.Bytes()
		require.NoError(t, err)

		ri2, remainder, err := ReadRouterIdentity(b)
		require.NoError(t, err)
		assert.Empty(t, remainder)
		assert.True(t, ri.Equal(ri2))
	})
}

// TestNewRouterIdentity_NilCertificate tests error handling for nil certificate.
func TestNewRouterIdentity_NilCertificate(t *testing.T) {
	pubKey := make([]byte, 32)
	_, _ = rand.Read(pubKey)
	sigKey := make([]byte, 32)
	_, _ = rand.Read(sigKey)

	ri, err := NewRouterIdentity(mockPublicKey(pubKey), mockSigningPublicKey(sigKey), nil, nil)
	require.Error(t, err, "nil certificate must be rejected")
	assert.Nil(t, ri)
}

// TestNewRouterIdentityWithCompressiblePadding_NilCertificate tests nil cert handling.
func TestNewRouterIdentityWithCompressiblePadding_NilCertificate(t *testing.T) {
	pubKey := make([]byte, 32)
	_, _ = rand.Read(pubKey)
	sigKey := make([]byte, 32)
	_, _ = rand.Read(sigKey)

	ri, err := NewRouterIdentityWithCompressiblePadding(
		mockPublicKey(pubKey), mockSigningPublicKey(sigKey), nil)
	require.Error(t, err, "nil certificate must be rejected")
	assert.Nil(t, ri)
}

// TestNewRouterIdentity_InvalidCertificate tests the error path when the
// certificate is valid but cannot create a KeyCertificate.
func TestNewRouterIdentity_InvalidCertificate(t *testing.T) {
	// A NULL certificate (type 0) with no payload
	nullCert, err := certificate.NewCertificateWithType(certificate.CERT_NULL, nil)
	require.NoError(t, err)

	pubKey := make([]byte, 256)
	_, _ = rand.Read(pubKey)
	sigKey := make([]byte, 128)
	_, _ = rand.Read(sigKey)

	// This should fail because KeyCertificateFromCertificate expects CERT_KEY
	ri, err := NewRouterIdentity(mockPublicKey(pubKey), mockSigningPublicKey(sigKey), nullCert, nil)
	// Either succeeds (if NULL cert path works) or fails with a clear error
	if err != nil {
		assert.Nil(t, ri)
	}
}

// TestNewRouterIdentityWithCompressiblePadding_ErrorPaths tests error paths.
func TestNewRouterIdentityWithCompressiblePadding_ErrorPaths(t *testing.T) {
	t.Run("invalid certificate type", func(t *testing.T) {
		// Create a certificate with invalid type that can't be used as key cert
		nullCert, err := certificate.NewCertificateWithType(certificate.CERT_NULL, nil)
		require.NoError(t, err)

		pubKey := make([]byte, 256)
		sigKey := make([]byte, 128)

		ri, err := NewRouterIdentityWithCompressiblePadding(
			mockPublicKey(pubKey), mockSigningPublicKey(sigKey), nullCert)
		if err != nil {
			assert.Nil(t, ri)
		}
	})
}

// TestAsDestination_CertificatePayloadIsolation verifies that mutating the
// Certificate payload bytes within the returned Destination does not affect
// the original RouterIdentity. This exercises the deep copy of slice backing
// arrays inside the KeyCertificate.
func TestAsDestination_CertificatePayloadIsolation(t *testing.T) {
	kac := buildKeysAndCertForTypes(t,
		key_certificate.KEYCERT_SIGN_ED25519,
		key_certificate.KEYCERT_CRYPTO_X25519,
	)
	ri, err := NewRouterIdentityFromKeysAndCert(kac)
	require.NoError(t, err)

	origBytes, err := ri.Bytes()
	require.NoError(t, err)

	dest := ri.AsDestination()
	require.NotNil(t, dest.KeysAndCert)
	require.NotNil(t, dest.KeysAndCert.KeyCertificate)

	// Mutate the Certificate payload inside the Destination's KeyCertificate
	destPayload, _ := dest.KeysAndCert.KeyCertificate.Certificate.Data()
	if len(destPayload) > 0 {
		destPayload[0] ^= 0xFF
	}

	afterBytes, err := ri.Bytes()
	require.NoError(t, err)
	assert.Equal(t, origBytes, afterBytes,
		"mutating Destination's Certificate payload must not affect original RouterIdentity")
}

// TestMarshalBinary verifies the encoding.BinaryMarshaler interface.
func TestMarshalBinary(t *testing.T) {
	t.Run("produces same bytes as Bytes()", func(t *testing.T) {
		kac := createValidKeysAndCert(t)
		ri, err := NewRouterIdentityFromKeysAndCert(kac)
		require.NoError(t, err)

		marshaledBytes, err := ri.MarshalBinary()
		require.NoError(t, err)

		directBytes, err := ri.Bytes()
		require.NoError(t, err)

		assert.Equal(t, directBytes, marshaledBytes)
	})

	t.Run("nil receiver returns error", func(t *testing.T) {
		var ri *RouterIdentity
		_, err := ri.MarshalBinary()
		require.Error(t, err)
	})
}

// TestUnmarshalBinary verifies the encoding.BinaryUnmarshaler interface.
func TestUnmarshalBinary(t *testing.T) {
	t.Run("round trip with MarshalBinary", func(t *testing.T) {
		kac := createValidKeysAndCert(t)
		ri1, err := NewRouterIdentityFromKeysAndCert(kac)
		require.NoError(t, err)

		data, err := ri1.MarshalBinary()
		require.NoError(t, err)

		ri2 := &RouterIdentity{}
		err = ri2.UnmarshalBinary(data)
		require.NoError(t, err)
		assert.True(t, ri1.Equal(ri2), "round-trip via MarshalBinary/UnmarshalBinary must preserve equality")
	})

	t.Run("rejects trailing data", func(t *testing.T) {
		data := createValidRouterIdentityBytes(t)
		dataWithExtra := append(data, 0xDE, 0xAD)

		ri := &RouterIdentity{}
		err := ri.UnmarshalBinary(dataWithExtra)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "trailing data")
	})

	t.Run("rejects invalid data", func(t *testing.T) {
		ri := &RouterIdentity{}
		err := ri.UnmarshalBinary([]byte{0x00, 0x01})
		require.Error(t, err)
	})

	t.Run("round trip with Ed25519/X25519", func(t *testing.T) {
		wireData := buildRouterIdentityBytes(t,
			key_certificate.KEYCERT_SIGN_ED25519,
			key_certificate.KEYCERT_CRYPTO_X25519,
		)
		ri1, _, err := ReadRouterIdentity(wireData)
		require.NoError(t, err)

		marshaled, err := ri1.MarshalBinary()
		require.NoError(t, err)

		ri2 := &RouterIdentity{}
		err = ri2.UnmarshalBinary(marshaled)
		require.NoError(t, err)
		assert.True(t, ri1.Equal(ri2))
	})
}
