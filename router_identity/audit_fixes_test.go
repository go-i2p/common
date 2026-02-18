package router_identity

import (
	"crypto/rand"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/go-i2p/common/certificate"
	"github.com/go-i2p/common/key_certificate"
	"github.com/go-i2p/common/keys_and_cert"
	"github.com/go-i2p/crypto/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============================================================
// Helper: build wire-format bytes for a RouterIdentity with
// specified signing and crypto key types.
// ============================================================

func buildKeyCertPayload(sigType, cryptoType int) []byte {
	payload := make([]byte, 4)
	binary.BigEndian.PutUint16(payload[0:2], uint16(sigType))
	binary.BigEndian.PutUint16(payload[2:4], uint16(cryptoType))
	return payload
}

// buildRouterIdentityBytes creates valid wire-format bytes for a RouterIdentity
// with the given signing and crypto key types (using KEY certificate type 5).
func buildRouterIdentityBytes(t *testing.T, sigType, cryptoType int) []byte {
	t.Helper()
	block := make([]byte, keys_and_cert.KEYS_AND_CERT_DATA_SIZE)
	_, err := rand.Read(block)
	require.NoError(t, err)

	certPayload := buildKeyCertPayload(sigType, cryptoType)
	certBytes := []byte{certificate.CERT_KEY}
	lenBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBytes, uint16(len(certPayload)))
	certBytes = append(certBytes, lenBytes...)
	certBytes = append(certBytes, certPayload...)
	return append(block, certBytes...)
}

// buildKeysAndCertForTypes creates a valid KeysAndCert with the given key types.
// Uses the constructor API (not wire parsing) to avoid layout issues with
// non-standard key sizes (e.g., RSA signing keys that exceed the default 128-byte slot).
func buildKeysAndCertForTypes(t *testing.T, sigType, cryptoType int) *keys_and_cert.KeysAndCert {
	t.Helper()

	keyCert, err := key_certificate.NewKeyCertificateWithTypes(sigType, cryptoType)
	require.NoError(t, err)

	sigKeySize := keyCert.SigningPublicKeySize()
	cryptoKeySize := keyCert.CryptoSize()

	pubKey := make([]byte, cryptoKeySize)
	_, _ = rand.Read(pubKey)
	sigKey := make([]byte, sigKeySize)
	_, _ = rand.Read(sigKey)
	paddingSize := keys_and_cert.KEYS_AND_CERT_DATA_SIZE - cryptoKeySize - sigKeySize
	var padding []byte
	if paddingSize > 0 {
		padding = make([]byte, paddingSize)
	}
	kac, err := keys_and_cert.NewKeysAndCert(keyCert, mockPublicKey(pubKey), padding, mockSigningPublicKey(sigKey))
	require.NoError(t, err)
	return kac
}

// ============================================================
// Finding #1 (BUG): Fuzz harness nil-pointer dereference
// Covered by fuzz/router_identity/fuzz.go fix (code change only).
// This test verifies ReadRouterIdentity returns nil on bad input.
// ============================================================

func TestAudit_ReadRouterIdentity_NilOnError(t *testing.T) {
	invalidData := []byte{0x00, 0x01, 0x02}
	ri, _, err := ReadRouterIdentity(invalidData)
	require.Error(t, err)
	assert.Nil(t, ri, "ReadRouterIdentity must return nil on error")
}

// ============================================================
// Findings #2, #3, #4 (SPEC): Key type restrictions
// ============================================================

func TestAudit_DisallowedSigningKeyTypes(t *testing.T) {
	// Test RedDSA via both ReadRouterIdentity and NewRouterIdentityFromKeysAndCert
	// (RedDSA has 32-byte keys, fits in standard layout)
	t.Run("RedDSA_via_ReadRouterIdentity", func(t *testing.T) {
		wireData := buildRouterIdentityBytes(t,
			key_certificate.KEYCERT_SIGN_REDDSA_ED25519,
			key_certificate.KEYCERT_CRYPTO_X25519,
		)
		ri, _, err := ReadRouterIdentity(wireData)
		require.Error(t, err)
		assert.Nil(t, ri)
		assert.Contains(t, err.Error(), "not permitted for Router Identities")
	})

	t.Run("RedDSA_via_NewRouterIdentityFromKeysAndCert", func(t *testing.T) {
		kac := buildKeysAndCertForTypes(t,
			key_certificate.KEYCERT_SIGN_REDDSA_ED25519,
			key_certificate.KEYCERT_CRYPTO_X25519,
		)
		ri, err := NewRouterIdentityFromKeysAndCert(kac)
		require.Error(t, err)
		assert.Nil(t, ri)
		assert.Contains(t, err.Error(), "not permitted for Router Identities")
	})

	// RSA-2048 fits in standard layout (256-byte signing key + 32-byte X25519 = 288 ≤ 384)
	t.Run("RSA-2048_via_NewRouterIdentityFromKeysAndCert", func(t *testing.T) {
		kac := buildKeysAndCertForTypes(t,
			key_certificate.KEYCERT_SIGN_RSA2048,
			key_certificate.KEYCERT_CRYPTO_X25519,
		)
		ri, err := NewRouterIdentityFromKeysAndCert(kac)
		require.Error(t, err)
		assert.Nil(t, ri)
		assert.Contains(t, err.Error(), "not permitted for Router Identities")
	})

	// RSA-3072 and RSA-4096 have signing keys (384/512 bytes) that exceed the
	// 384-byte KeysAndCert data block when combined with any crypto key type.
	// We test the validation function directly for these types.
	t.Run("RSA-3072_direct_validation", func(t *testing.T) {
		err := validateRouterIdentityKeyTypes(
			buildMinimalKacWithTypes(t, key_certificate.KEYCERT_SIGN_RSA3072, key_certificate.KEYCERT_CRYPTO_ELG),
		)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not permitted for Router Identities")
	})

	t.Run("RSA-4096_direct_validation", func(t *testing.T) {
		err := validateRouterIdentityKeyTypes(
			buildMinimalKacWithTypes(t, key_certificate.KEYCERT_SIGN_RSA4096, key_certificate.KEYCERT_CRYPTO_ELG),
		)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not permitted for Router Identities")
	})
}

// buildMinimalKacWithTypes creates a KeysAndCert with only the KeyCertificate set,
// sufficient for key type validation. Used for types that can't be fully constructed.
func buildMinimalKacWithTypes(t *testing.T, sigType, cryptoType int) *keys_and_cert.KeysAndCert {
	t.Helper()
	keyCert, err := key_certificate.NewKeyCertificateWithTypes(sigType, cryptoType)
	require.NoError(t, err)
	return &keys_and_cert.KeysAndCert{KeyCertificate: keyCert}
}

func TestAudit_DisallowedCryptoKeyTypes(t *testing.T) {
	tests := []struct {
		name       string
		cryptoType int
	}{
		{"MLKEM512_X25519", key_certificate.KEYCERT_CRYPTO_MLKEM512_X25519},
		{"MLKEM768_X25519", key_certificate.KEYCERT_CRYPTO_MLKEM768_X25519},
		{"MLKEM1024_X25519", key_certificate.KEYCERT_CRYPTO_MLKEM1024_X25519},
	}
	for _, tt := range tests {
		t.Run(tt.name+"_via_ReadRouterIdentity", func(t *testing.T) {
			wireData := buildRouterIdentityBytes(t, key_certificate.KEYCERT_SIGN_ED25519, tt.cryptoType)
			ri, _, err := ReadRouterIdentity(wireData)
			// ReadKeysAndCert may reject MLKEM types before our validation runs.
			// Either way, the result must be an error with nil RouterIdentity.
			require.Error(t, err, "crypto type %d must be rejected", tt.cryptoType)
			assert.Nil(t, ri)
		})
		t.Run(tt.name+"_via_NewRouterIdentityFromKeysAndCert", func(t *testing.T) {
			// Build KAC directly with the MLKEM type set in the KeyCertificate
			kac := &keys_and_cert.KeysAndCert{}
			keyCert, err := key_certificate.NewKeyCertificateWithTypes(
				key_certificate.KEYCERT_SIGN_ED25519, tt.cryptoType,
			)
			require.NoError(t, err)
			kac.KeyCertificate = keyCert
			// Use validateRouterIdentityKeyTypes directly since these can't be
			// constructed via NewKeysAndCert (unsupported crypto type).
			err = validateRouterIdentityKeyTypes(kac)
			require.Error(t, err, "crypto type %d must be rejected", tt.cryptoType)
			assert.Contains(t, err.Error(), "not permitted for Router Identities")
		})
	}
}

// ============================================================
// Finding #5 (BUG): AsDestination panics on nil receiver
// ============================================================

func TestAudit_AsDestination_NilReceiver(t *testing.T) {
	var ri *RouterIdentity
	// Must not panic
	dest := ri.AsDestination()
	assert.Nil(t, dest.KeysAndCert, "nil receiver should produce zero-value Destination")
}

func TestAudit_AsDestination_NilKeysAndCert(t *testing.T) {
	ri := &RouterIdentity{KeysAndCert: nil}
	// Must not panic
	dest := ri.AsDestination()
	assert.Nil(t, dest.KeysAndCert, "nil KeysAndCert should produce zero-value Destination")
}

// ============================================================
// Finding #6 (GAP): Equal() method
// ============================================================

func TestAudit_Equal(t *testing.T) {
	t.Run("identical identities are equal", func(t *testing.T) {
		kac := createValidKeysAndCert(t)
		ri1, err := NewRouterIdentityFromKeysAndCert(kac)
		require.NoError(t, err)

		// Parse the same bytes back
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
}

// ============================================================
// Finding #7 (GAP): fmt.Stringer implementation
// ============================================================

func TestAudit_String(t *testing.T) {
	t.Run("valid identity produces hash string", func(t *testing.T) {
		kac := createValidKeysAndCert(t)
		ri, err := NewRouterIdentityFromKeysAndCert(kac)
		require.NoError(t, err)

		s := ri.String()
		assert.True(t, strings.HasPrefix(s, "RouterIdentity{"))
		assert.True(t, strings.HasSuffix(s, "}"))
		// Should contain hex chars between braces
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

// ============================================================
// Finding #9 (GAP): Deprecation warnings for legacy key types
// (Verified by code presence; logging side-effects not tested
// beyond confirming construction still succeeds for legacy types.)
// ============================================================

func TestAudit_DeprecatedKeyTypes_StillAccepted(t *testing.T) {
	// ElGamal + DSA-SHA1 (deprecated but still accepted)
	wireData := createValidRouterIdentityBytes(t)
	ri, _, err := ReadRouterIdentity(wireData)
	require.NoError(t, err, "deprecated key types should still be accepted with warnings")
	assert.NotNil(t, ri)
}

// ============================================================
// Finding #10 (TEST): Test for NewRouterIdentity constructor
// ============================================================

func TestAudit_NewRouterIdentity(t *testing.T) {
	t.Run("valid construction with Ed25519/X25519", func(t *testing.T) {
		// Build a valid KeyCertificate for Ed25519/X25519
		keyCert, err := key_certificate.NewKeyCertificateWithTypes(
			key_certificate.KEYCERT_SIGN_ED25519,
			key_certificate.KEYCERT_CRYPTO_X25519,
		)
		require.NoError(t, err)

		pubKey := make([]byte, 32) // X25519
		_, _ = rand.Read(pubKey)
		sigKey := make([]byte, 32) // Ed25519
		_, _ = rand.Read(sigKey)

		// Calculate padding: 384 - 32 - 32 = 320
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

// ============================================================
// Finding #14 (TEST): Round-trip byte equality
// ============================================================

func TestAudit_RoundTripByteEquality(t *testing.T) {
	kac := createValidKeysAndCert(t)
	ri1, err := NewRouterIdentityFromKeysAndCert(kac)
	require.NoError(t, err)

	bytes1, err := ri1.KeysAndCert.Bytes()
	require.NoError(t, err)

	ri2, remainder, err := NewRouterIdentityFromBytes(bytes1)
	require.NoError(t, err)
	assert.Empty(t, remainder)

	bytes2, err := ri2.KeysAndCert.Bytes()
	require.NoError(t, err)

	assert.Equal(t, bytes1, bytes2, "round-trip bytes must be identical")
	assert.True(t, ri1.Equal(ri2), "round-trip identities must be Equal()")
}

// ============================================================
// Finding #8 (GAP): ReadRouterIdentity return pattern
// (Acknowledged — changing return type would break API.)
// This test documents the current behavior.
// ============================================================

func TestAudit_ReadRouterIdentity_ReturnsNilOnError(t *testing.T) {
	ri, remainder, err := ReadRouterIdentity([]byte{0x00})
	require.Error(t, err)
	assert.Nil(t, ri, "ReadRouterIdentity returns nil pointer on error")
	_ = remainder
}

// ============================================================
// Mock types for NewRouterIdentity tests
// ============================================================

type mockPublicKey []byte

func (m mockPublicKey) Len() int                               { return len(m) }
func (m mockPublicKey) Bytes() []byte                          { return []byte(m) }
func (m mockPublicKey) NewEncrypter() (types.Encrypter, error) { return nil, nil }

type mockSigningPublicKey []byte

func (m mockSigningPublicKey) Len() int                             { return len(m) }
func (m mockSigningPublicKey) Bytes() []byte                        { return []byte(m) }
func (m mockSigningPublicKey) NewVerifier() (types.Verifier, error) { return nil, nil }
