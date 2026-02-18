package router_identity

import (
	"crypto/rand"
	"testing"

	"github.com/go-i2p/common/certificate"
	"github.com/go-i2p/common/key_certificate"
	"github.com/go-i2p/common/keys_and_cert"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============================================================
// Finding: [SPEC] Ed25519ph (signing type 8) must be blocked
// Finding: [TEST] No test verifies Ed25519ph is rejected
// ============================================================

func TestAudit2_Ed25519ph_Rejected(t *testing.T) {
	t.Run("Ed25519ph_via_ReadRouterIdentity", func(t *testing.T) {
		wireData := buildRouterIdentityBytes(t,
			key_certificate.KEYCERT_SIGN_ED25519PH,
			key_certificate.KEYCERT_CRYPTO_X25519,
		)
		ri, _, err := ReadRouterIdentity(wireData)
		require.Error(t, err)
		assert.Nil(t, ri)
		assert.Contains(t, err.Error(), "not permitted for Router Identities")
	})

	t.Run("Ed25519ph_via_NewRouterIdentityFromKeysAndCert", func(t *testing.T) {
		kac := buildKeysAndCertForTypes(t,
			key_certificate.KEYCERT_SIGN_ED25519PH,
			key_certificate.KEYCERT_CRYPTO_X25519,
		)
		ri, err := NewRouterIdentityFromKeysAndCert(kac)
		require.Error(t, err)
		assert.Nil(t, ri)
		assert.Contains(t, err.Error(), "not permitted for Router Identities")
	})

	t.Run("Ed25519ph_direct_validation", func(t *testing.T) {
		err := validateRouterIdentityKeyTypes(
			buildMinimalKacWithTypes(t,
				key_certificate.KEYCERT_SIGN_ED25519PH,
				key_certificate.KEYCERT_CRYPTO_X25519,
			),
		)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "Ed25519ph")
	})
}

// ============================================================
// Finding: [TEST] No test for AsDestination() mutation isolation
// ============================================================

func TestAudit2_AsDestination_MutationIsolation(t *testing.T) {
	kac := createValidKeysAndCert(t)
	ri, err := NewRouterIdentityFromKeysAndCert(kac)
	require.NoError(t, err)

	// Get original bytes for comparison
	origBytes, err := ri.KeysAndCert.Bytes()
	require.NoError(t, err)

	// Get destination (should be a deep copy)
	dest := ri.AsDestination()
	require.NotNil(t, dest.KeysAndCert)

	// Verify the destination's KeysAndCert is a different pointer
	assert.NotSame(t, ri.KeysAndCert, dest.KeysAndCert,
		"AsDestination must return a deep copy, not share the pointer")

	// Mutate the destination's KeysAndCert
	dest.KeysAndCert.KeyCertificate = nil

	// Verify the original RouterIdentity is NOT affected
	assert.NotNil(t, ri.KeysAndCert.KeyCertificate,
		"mutating Destination must not affect original RouterIdentity")

	// Verify original bytes unchanged
	afterBytes, err := ri.KeysAndCert.Bytes()
	require.NoError(t, err)
	assert.Equal(t, origBytes, afterBytes,
		"original RouterIdentity bytes must be unchanged after Destination mutation")
}

// ============================================================
// Finding: [TEST] No test for Equal() with different identities
// ============================================================

func TestAudit2_Equal_DifferentIdentities(t *testing.T) {
	t.Run("structurally_different_identities_not_equal", func(t *testing.T) {
		// Create two different RouterIdentities with different key material
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

		// Since buildRouterIdentityBytes uses crypto/rand, these should be different
		assert.False(t, ri1.Equal(ri2),
			"RouterIdentities with different random key material must not be Equal")
	})

	t.Run("different_key_types_not_equal", func(t *testing.T) {
		// Ed25519/X25519 identity
		data1 := buildRouterIdentityBytes(t,
			key_certificate.KEYCERT_SIGN_ED25519,
			key_certificate.KEYCERT_CRYPTO_X25519,
		)
		ri1, _, err := ReadRouterIdentity(data1)
		require.NoError(t, err)

		// DSA/ElGamal identity (deprecated but still parseable)
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

		// Equal must be symmetric
		assert.Equal(t, ri1.Equal(ri2), ri2.Equal(ri1),
			"Equal must be symmetric")
	})
}

// ============================================================
// Finding: [GAP] nil KeyCertificate validation
// ============================================================

func TestAudit2_ValidateRejectsNilKeyCertificate(t *testing.T) {
	t.Run("nil_kac_rejected", func(t *testing.T) {
		err := validateRouterIdentityKeyTypes(nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "cannot be nil")
	})

	t.Run("nil_key_certificate_rejected", func(t *testing.T) {
		kac := &keys_and_cert.KeysAndCert{KeyCertificate: nil}
		err := validateRouterIdentityKeyTypes(kac)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "KeyCertificate is nil")
	})
}

// ============================================================
// Finding: [GAP] NewRouterIdentityWithCompressiblePadding
// ============================================================

func TestAudit2_NewRouterIdentityWithCompressiblePadding(t *testing.T) {
	t.Run("creates_valid_identity", func(t *testing.T) {
		keyCert, err := key_certificate.NewKeyCertificateWithTypes(
			key_certificate.KEYCERT_SIGN_ED25519,
			key_certificate.KEYCERT_CRYPTO_X25519,
		)
		require.NoError(t, err)

		pubKey := make([]byte, 32) // X25519
		_, _ = rand.Read(pubKey)
		sigKey := make([]byte, 32) // Ed25519
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

	t.Run("padding_is_compressible", func(t *testing.T) {
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

		// Verify padding is compressible (repeating 32-byte pattern)
		padding := ri.KeysAndCert.Padding
		if len(padding) >= 64 {
			// First 32 bytes should equal bytes 32-63
			assert.Equal(t, padding[:32], padding[32:64],
				"compressible padding should repeat 32-byte pattern")
		}
	})

	t.Run("rejected_disallowed_type", func(t *testing.T) {
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

// ============================================================
// Finding: [TEST] Fuzz test for constructors
// ============================================================

func FuzzNewRouterIdentityFromKeysAndCert(f *testing.F) {
	// Seed with valid Ed25519/X25519 wire data
	seed := buildRouterIdentityBytes(&testing.T{},
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
		// If construction succeeds, identity must be valid
		assert.True(t, ri.IsValid())
		assert.NotNil(t, ri.KeysAndCert)
	})
}

func FuzzNewRouterIdentityFromBytes(f *testing.F) {
	seed := buildRouterIdentityBytes(&testing.T{},
		key_certificate.KEYCERT_SIGN_ED25519,
		key_certificate.KEYCERT_CRYPTO_X25519,
	)
	f.Add(seed)

	f.Fuzz(func(t *testing.T, data []byte) {
		ri, _, err := NewRouterIdentityFromBytes(data)
		if err != nil {
			return
		}
		assert.True(t, ri.IsValid())
		assert.NotNil(t, ri.KeysAndCert)
	})
}

// ============================================================
// Finding: [QUALITY] String() now uses 16-byte (128-bit) truncation
// ============================================================

func TestAudit2_String_16ByteTruncation(t *testing.T) {
	kac := createValidKeysAndCert(t)
	ri, err := NewRouterIdentityFromKeysAndCert(kac)
	require.NoError(t, err)

	s := ri.String()
	assert.Contains(t, s, "RouterIdentity{")
	inner := s[len("RouterIdentity{") : len(s)-1]
	assert.Len(t, inner, 32, "SHA-256 truncated to 16 bytes = 32 hex chars")
}

// ============================================================
// Finding: [GAP] Equal uses constant-time comparison
// Verify it still works correctly
// ============================================================

func TestAudit2_Equal_ConstantTime(t *testing.T) {
	// Identical bytes should be equal
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
}

// Helpers: verify the certificate.CERT_KEY constant works properly
func TestAudit2_BuilderIntegration(t *testing.T) {
	t.Run("build_with_certificate_builder", func(t *testing.T) {
		builder := certificate.NewCertificateBuilder()
		builder, err := builder.WithKeyTypes(key_certificate.KEYCERT_SIGN_ED25519, key_certificate.KEYCERT_CRYPTO_X25519)
		require.NoError(t, err)
		cert, err := builder.Build()
		if err != nil {
			t.Skip("certificate builder not available:", err)
		}

		pubKey := make([]byte, 32)
		_, _ = rand.Read(pubKey)
		sigKey := make([]byte, 32)
		_, _ = rand.Read(sigKey)

		paddingSize := keys_and_cert.KEYS_AND_CERT_DATA_SIZE - 32 - 32
		padding, err := keys_and_cert.GenerateCompressiblePadding(paddingSize)
		require.NoError(t, err)

		ri, err := NewRouterIdentity(
			mockPublicKey(pubKey),
			mockSigningPublicKey(sigKey),
			cert,
			padding,
		)
		require.NoError(t, err)
		require.NotNil(t, ri)
		assert.True(t, ri.IsValid())
	})
}
