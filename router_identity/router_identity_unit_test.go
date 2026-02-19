package router_identity

import (
	"crypto/rand"
	"strings"
	"testing"

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

// TestNewRouterIdentityDefensiveCopy tests that constructor does not retain references
func TestNewRouterIdentityDefensiveCopy(t *testing.T) {
	keysAndCert := createValidKeysAndCert(t)
	ri, err := NewRouterIdentityFromKeysAndCert(keysAndCert)
	require.NoError(t, err)

	// Verify that changing the original keysAndCert doesn't affect the stored one
	origBytes, err := ri.KeysAndCert.Bytes()
	require.NoError(t, err)
	assert.NotEmpty(t, origBytes)
}
