package encrypted_leaseset

import (
	"testing"

	"github.com/go-i2p/crypto/rand"

	"github.com/go-i2p/common/key_certificate"
	goi2ped25519 "github.com/go-i2p/crypto/ed25519"
	cryptoRed25519 "github.com/go-i2p/crypto/red25519"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ————————————————————————————————————————————————
// Integration tests for constructor round-trips
// Source: constructor.go
// ————————————————————————————————————————————————

func TestNewEncryptedLeaseSetRoundTrip(t *testing.T) {
	ls2, encryptedData, subcredential, published := createTestEncryptionContext(t)

	_, signingPriv, err := goi2ped25519.GenerateEd25519KeyPair()
	require.NoError(t, err)

	blindedKey := make([]byte, 32)
	_, _ = rand.Read(blindedKey)

	original, err := NewEncryptedLeaseSet(
		key_certificate.KEYCERT_SIGN_ED25519,
		blindedKey,
		published,
		600,
		0,
		nil,
		encryptedData,
		signingPriv,
	)
	require.NoError(t, err)

	serialized, err := original.Bytes()
	require.NoError(t, err)

	parsed, remainder, err := ReadEncryptedLeaseSet(serialized)
	require.NoError(t, err)
	assert.Empty(t, remainder)

	assert.Equal(t, original.SigType(), parsed.SigType())
	assert.Equal(t, original.BlindedPublicKey(), parsed.BlindedPublicKey())
	assert.Equal(t, original.Published(), parsed.Published())
	assert.Equal(t, original.Expires(), parsed.Expires())
	assert.Equal(t, original.Flags(), parsed.Flags())
	assert.Equal(t, original.InnerLength(), parsed.InnerLength())
	assert.Equal(t, original.EncryptedInnerData(), parsed.EncryptedInnerData())

	// Verify decryption still works after round-trip through serialization
	decrypted, err := parsed.DecryptInnerData(subcredential)
	require.NoError(t, err)
	assert.NotNil(t, decrypted)
	assert.Equal(t, ls2.Published(), decrypted.Published())
}

func TestEncryptedLeaseSetValidateViaConstructor(t *testing.T) {
	_, encryptedData, _, published := createTestEncryptionContext(t)

	_, signingPriv, err := goi2ped25519.GenerateEd25519KeyPair()
	require.NoError(t, err)

	blindedKey := make([]byte, 32)
	_, _ = rand.Read(blindedKey)

	els, err := NewEncryptedLeaseSet(
		key_certificate.KEYCERT_SIGN_ED25519,
		blindedKey,
		published,
		600,
		0,
		nil,
		encryptedData,
		signingPriv,
	)
	require.NoError(t, err)

	assert.NoError(t, els.Validate())
	assert.True(t, els.IsValid())
}

// TestNewEncryptedLeaseSetRedDSARoundTrip exercises the spec-mandated signing
// path for an EncryptedLeaseSet: encryptedleaseset.md §"Signing" says the outer
// signature uses Red25519 with the blinded key, and §"Blinding Calculations"
// states the blinded signing key "will always be type 11". A real Red25519
// keypair signs, the bytes round-trip through the parser, and Verify() accepts
// using the Red25519 (HStar + cofactor) rule.
func TestNewEncryptedLeaseSetRedDSARoundTrip(t *testing.T) {
	ls2, encryptedData, subcredential, published := createTestEncryptionContext(t)

	// A genuine Red25519 keypair stands in for the blinded key A'/a'.
	_, blindedPriv, err := cryptoRed25519.GenerateRed25519KeyPair()
	require.NoError(t, err)
	blindedPub, err := blindedPriv.Public()
	require.NoError(t, err)

	els, err := NewEncryptedLeaseSet(
		key_certificate.KEYCERT_SIGN_REDDSA_ED25519,
		blindedPub.Bytes(),
		published,
		600,
		0,
		nil,
		encryptedData,
		*blindedPriv,
	)
	require.NoError(t, err)

	// The outer signature must verify against the blinded public key.
	require.NoError(t, els.Verify(), "type 11 outer signature must verify")

	serialized, err := els.Bytes()
	require.NoError(t, err)

	parsed, remainder, err := ReadEncryptedLeaseSet(serialized)
	require.NoError(t, err)
	assert.Empty(t, remainder)
	assert.Equal(t, els.SigType(), parsed.SigType())
	assert.Equal(t, els.BlindedPublicKey(), parsed.BlindedPublicKey())

	// The parsed record still verifies, and its inner data still decrypts.
	require.NoError(t, parsed.Verify())
	decrypted, err := parsed.DecryptInnerData(subcredential)
	require.NoError(t, err)
	assert.Equal(t, ls2.Published(), decrypted.Published())
}

// TestNewEncryptedLeaseSetRedDSASignatureIsRandomized asserts the unlinkability
// property the spec requires of the blinded outer signature: two EncryptedLeaseSets
// built from the same key and inner data differ in their signature bytes, so an
// observer cannot correlate re-publications.
func TestNewEncryptedLeaseSetRedDSASignatureIsRandomized(t *testing.T) {
	_, encryptedData, _, published := createTestEncryptionContext(t)

	_, blindedPriv, err := cryptoRed25519.GenerateRed25519KeyPair()
	require.NoError(t, err)
	blindedPub, err := blindedPriv.Public()
	require.NoError(t, err)

	newELS := func() []byte {
		els, err := NewEncryptedLeaseSet(
			key_certificate.KEYCERT_SIGN_REDDSA_ED25519,
			blindedPub.Bytes(),
			published,
			600,
			0,
			nil,
			encryptedData,
			*blindedPriv,
		)
		require.NoError(t, err)
		b, err := els.Bytes()
		require.NoError(t, err)
		return b
	}

	a, b := newELS(), newELS()
	// Only the trailing 64-byte signature should differ; everything before it
	// (sigtype, blinded key, published, expires, flags, len, ciphertext) is equal.
	require.Len(t, a, len(b))
	assert.Equal(t, a[:len(a)-64], b[:len(b)-64],
		"non-signature prefix must be identical for the same inputs")
	assert.NotEqual(t, a[len(a)-64:], b[len(b)-64:],
		"RedDSA signature must be randomized per publication")
}
