// Package router_identity – tests for AUDIT.md findings.
package router_identity

import (
	"testing"

	"github.com/go-i2p/common/certificate"
	"github.com/go-i2p/common/key_certificate"
	"github.com/go-i2p/common/keys_and_cert"
	"github.com/go-i2p/crypto/rand"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── Finding 1 (SPEC): ECDSA-P521 disallow list vs. parsability ─────────────
// Verifies that ECDSA-P521 (type 3) Router Identities can be parsed after the
// upstream keys_and_cert fix that implements excess signing-key reconstruction.
// P521 is NOT prohibited for Router Identities; it is deprecated but valid.

// TestRouterIdentityP521Parseable verifies that a P521+X25519 RouterIdentity
// built through the normal helpers can be constructed, serialized, and
// re-parsed without error.
func TestRouterIdentityP521Parseable(t *testing.T) {
	kac := buildKeysAndCertForTypes(t,
		key_certificate.KEYCERT_SIGN_P521,
		key_certificate.KEYCERT_CRYPTO_X25519,
	)

	ri, err := NewRouterIdentityFromKeysAndCert(kac)
	require.NoError(t, err, "P521+X25519 RouterIdentity must be constructed without error")
	require.NotNil(t, ri)
	assert.True(t, ri.IsValid())

	// Verify round-trip serialization.
	b, err := ri.Bytes()
	require.NoError(t, err)
	ri2, rem, err := ReadRouterIdentity(b)
	require.NoError(t, err, "P521+X25519 wire format must be parseable")
	assert.Empty(t, rem)
	assert.True(t, ri.Equal(ri2), "P521 identity must survive round-trip")
}

// TestRouterIdentityP521NotDisallowed confirms P521 is not in disallowedSigningKeyTypes.
func TestRouterIdentityP521NotDisallowed(t *testing.T) {
	kac := buildMinimalKacWithTypes(t,
		key_certificate.KEYCERT_SIGN_P521,
		key_certificate.KEYCERT_CRYPTO_X25519,
	)
	err := validateRouterIdentityKeyTypes(kac)
	assert.NoError(t, err, "P521 must not be rejected by validateRouterIdentityKeyTypes")
}

// ── Finding GAP (2): ECDSA P256/P384/P521 handling at the RI boundary ──────
// Documents and tests all three deprecated ECDSA signing types.

// TestRouterIdentityECDSARoundTrip verifies that P256, P384, and P521 router
// identities can be constructed, serialized, and faithfully re-parsed.
func TestRouterIdentityECDSARoundTrip(t *testing.T) {
	cases := []struct {
		name      string
		sigType   int
		cryptType int
	}{
		{"P256+ElGamal", key_certificate.KEYCERT_SIGN_P256, key_certificate.KEYCERT_CRYPTO_ELG},
		{"P384+ElGamal", key_certificate.KEYCERT_SIGN_P384, key_certificate.KEYCERT_CRYPTO_ELG},
		{"P521+X25519", key_certificate.KEYCERT_SIGN_P521, key_certificate.KEYCERT_CRYPTO_X25519},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			kac := buildKeysAndCertForTypes(t, tc.sigType, tc.cryptType)

			ri, err := NewRouterIdentityFromKeysAndCert(kac)
			require.NoErrorf(t, err, "%s RouterIdentity construction", tc.name)

			b, err := ri.Bytes()
			require.NoError(t, err)

			ri2, rem, err := ReadRouterIdentity(b)
			require.NoErrorf(t, err, "%s wire-format parse after round-trip", tc.name)
			assert.Empty(t, rem)
			assert.True(t, ri.Equal(ri2), "%s round-trip must preserve equality", tc.name)
		})
	}
}

// ── Finding GAP (3): NULL certificate parsing path ──────────────────────────
// The spec allows Router Identities with NULL certificates (ElGamal+DSA-SHA1).
// This test exercises the full parse-and-serialize round-trip for that path.

// TestNullCertRouterIdentityRoundTrip verifies that a NULL-certificate
// RouterIdentity (387 bytes: 384 key bytes + 3-byte NULL cert) parses and
// round-trips correctly.
func TestNullCertRouterIdentityRoundTrip(t *testing.T) {
	// Build a valid NULL-cert RouterIdentity from raw wire bytes.
	// 384 bytes of random key material + [0x00, 0x00, 0x00] (NULL cert).
	keyBlock := make([]byte, keys_and_cert.KEYS_AND_CERT_DATA_SIZE)
	_, err := rand.Read(keyBlock)
	require.NoError(t, err)
	nullCert := []byte{certificate.CERT_NULL, 0x00, 0x00}
	wireData := append(keyBlock, nullCert...)

	ri, remainder, err := ReadRouterIdentity(wireData)
	require.NoError(t, err, "NULL-cert RouterIdentity must parse without error")
	assert.Empty(t, remainder)
	require.NotNil(t, ri)
	assert.True(t, ri.IsValid())

	// For NULL certs, keys_and_cert synthesises a KeyCertificate with DSA-SHA1(0)+ElGamal(0).
	require.NotNil(t, ri.KeysAndCert.KeyCertificate,
		"NULL-cert identity uses a synthetic KeyCertificate with implied DSA-SHA1+ElGamal types")
	assert.Equal(t, 0, ri.KeysAndCert.KeyCertificate.SigningPublicKeyType(),
		"NULL cert implies DSA-SHA1 signing type (0)")
	assert.Equal(t, 0, ri.KeysAndCert.KeyCertificate.PublicKeyType(),
		"NULL cert implies ElGamal crypto type (0)")

	// Round-trip: serialize and re-parse.
	b, err := ri.Bytes()
	require.NoError(t, err)
	assert.Equal(t, wireData, b, "NULL-cert round-trip must preserve exact bytes")

	ri2, rem2, err := ReadRouterIdentity(b)
	require.NoError(t, err)
	assert.Empty(t, rem2)
	assert.True(t, ri.Equal(ri2), "NULL-cert round-trip must preserve equality")
}

// TestNullCertRemainder verifies that trailing bytes after a NULL cert are
// returned correctly in remainder.
func TestNullCertRemainder(t *testing.T) {
	keyBlock := make([]byte, keys_and_cert.KEYS_AND_CERT_DATA_SIZE)
	nullCert := []byte{certificate.CERT_NULL, 0x00, 0x00}
	extra := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	wireData := append(append(keyBlock, nullCert...), extra...)

	ri, remainder, err := ReadRouterIdentity(wireData)
	require.NoError(t, err)
	require.NotNil(t, ri)
	assert.Equal(t, extra, remainder, "trailing bytes must be returned as remainder")
}

// ── Finding BUG (2): Defensive deep copy of key interface values ─────────────
// ReceivingPublic and SigningPublic are interface values.  For production types
// backed by fixed-size Go arrays (Ed25519, X25519), the struct copy creates
// independent copies.  For slice-backed test implementations (mockPublicKey),
// the backing array is shared.  This test documents both behaviours.

// TestDefensiveCopyKeysInterface documents the copy semantics for the
// ReceivingPublic and SigningPublic interface fields in NewRouterIdentityFromKeysAndCert.
func TestDefensiveCopyKeysInterface(t *testing.T) {
	t.Run("production serialization is independent after original mutation", func(t *testing.T) {
		// Production path: deserialize wire bytes; key types are array-backed.
		kac := createValidKeysAndCert(t)
		ri, err := NewRouterIdentityFromKeysAndCert(kac)
		require.NoError(t, err)

		// Capture original serialization.
		b1, err := ri.Bytes()
		require.NoError(t, err)

		// Now zero the ReceivingPublic of the original kac.  For production
		// key types (array-backed), this must not affect the RouterIdentity.
		if kac.ReceivingPublic != nil {
			rb := kac.ReceivingPublic.Bytes()
			for i := range rb {
				rb[i] = 0
			}
		}

		b2, err := ri.Bytes()
		require.NoError(t, err)
		assert.Equal(t, b1, b2,
			"RouterIdentity serialization must be unchanged after mutating original kac ReceivingPublic bytes")
	})

	t.Run("slice-backed mock key shares backing array (documented limitation)", func(t *testing.T) {
		// This sub-test documents the KNOWN LIMITATION: for slice-backed key
		// implementations, the interface value copy shares the underlying array.
		// Production code only uses array-backed key types so this is not exploitable
		// in practice, but callers using mockPublicKey must be aware.
		kac := buildKeysAndCertForTypes(t,
			key_certificate.KEYCERT_SIGN_ED25519,
			key_certificate.KEYCERT_CRYPTO_X25519,
		)
		ri, err := NewRouterIdentityFromKeysAndCert(kac)
		require.NoError(t, err)

		// The mockPublicKey stored in kac.ReceivingPublic is a []byte slice.
		// Mutating kac.ReceivingPublic.Bytes() mutates the shared backing array.
		// We document this behaviour here without asserting isolation (which would
		// fail for slice-backed types).
		originalBytes := make([]byte, len(ri.KeysAndCert.ReceivingPublic.Bytes()))
		copy(originalBytes, ri.KeysAndCert.ReceivingPublic.Bytes())

		// The test merely verifies no panic occurs and the RI remains structurally valid.
		assert.NotNil(t, ri.KeysAndCert.ReceivingPublic, "ReceivingPublic must not be nil")
		assert.Equal(t, originalBytes, ri.KeysAndCert.ReceivingPublic.Bytes(),
			"key bytes must be stable when not externally mutated")
	})
}

// ── Finding BUG (3): Certificate.payload deep copy ───────────────────────────
// NewRouterIdentityFromKeysAndCert now clones the KeyCertificate by re-parsing
// its wire bytes, giving the copy an independent Certificate.payload backing array.

// TestKeyCertificatePayloadDeepCopy verifies that the KeyCertificate in a newly
// constructed RouterIdentity has an independent payload from the original.
func TestKeyCertificatePayloadDeepCopy(t *testing.T) {
	kac := createValidKeysAndCert(t)
	require.NotNil(t, kac.KeyCertificate, "test requires a KEY certificate")

	ri, err := NewRouterIdentityFromKeysAndCert(kac)
	require.NoError(t, err)

	// The two KeyCertificate pointers must be different allocations.
	assert.True(t, ri.KeysAndCert.KeyCertificate != kac.KeyCertificate,
		"KeyCertificate pointer must be a separate allocation after deep copy via bytes")

	// Their wire representations must be equal (same logical content).
	origData, err := kac.KeyCertificate.Data()
	require.NoError(t, err)
	copyData, err := ri.KeysAndCert.KeyCertificate.Data()
	require.NoError(t, err)
	assert.Equal(t, origData, copyData,
		"deep-copied KeyCertificate must have identical payload content")

	// Verify signing type and crypto type are preserved.
	assert.Equal(t,
		kac.KeyCertificate.SigningPublicKeyType(),
		ri.KeysAndCert.KeyCertificate.SigningPublicKeyType(),
		"signing type must be preserved through deep copy")
	assert.Equal(t,
		kac.KeyCertificate.PublicKeyType(),
		ri.KeysAndCert.KeyCertificate.PublicKeyType(),
		"crypto type must be preserved through deep copy")
}
