package encrypted_leaseset

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/go-i2p/common/key_certificate"
	"github.com/go-i2p/common/offline_signature"
	sigpkg "github.com/go-i2p/common/signature"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Regression tests for the EncryptedLeaseSet offline-signature bypass.
//
// Before the fix, Verify() resolved the transient signing key straight out of
// the OfflineSignature whenever the offline-keys flag was set, without ever
// checking the offline signature itself. Anyone could therefore pick a
// transient key, put random bytes in the offline signature field, sign the
// EncryptedLeaseSet with the chosen key, and have it verify as any blinded
// identity.
//
// Per the encrypted leaseset spec the offline signature is "Over expires
// timestamp, transient sig type, and transient public key. Verified with the
// blinded public key.", so the authorizing key here is the blinded public key
// carried in the structure.

const encTestInnerSize = 80

// newForgedEncOfflineSignature builds an OfflineSignature whose signature field
// is random bytes — the destination/blinded key never authorized it.
func newForgedEncOfflineSignature(t *testing.T, transientPub ed25519.PublicKey, expires uint32) offline_signature.OfflineSignature {
	t.Helper()
	forged := make([]byte, sigpkg.EdDSA_SHA512_Ed25519_SIZE)
	_, err := rand.Read(forged)
	require.NoError(t, err)

	offSig, err := offline_signature.NewOfflineSignature(
		expires,
		uint16(key_certificate.KEYCERT_SIGN_ED25519),
		transientPub,
		forged,
		uint16(key_certificate.KEYCERT_SIGN_ED25519),
	)
	require.NoError(t, err)
	return offSig
}

func encTestInnerData() []byte {
	encData := make([]byte, encTestInnerSize)
	for i := range encData {
		encData[i] = byte(i)
	}
	return encData
}

// TestVerifyRejectsForgedOfflineSignature is the core forgery: attacker-chosen
// transient key + random offline signature bytes + outer signature made with
// the attacker's transient key MUST NOT verify.
func TestVerifyRejectsForgedOfflineSignature(t *testing.T) {
	// Blinded identity the attacker wants to impersonate.
	blindedPub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	transientPub, transientPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	offSig := newForgedEncOfflineSignature(t, transientPub, uint32(time.Now().Add(24*time.Hour).Unix()))

	els, err := NewEncryptedLeaseSet(
		uint16(key_certificate.KEYCERT_SIGN_ED25519),
		blindedPub,
		uint32(time.Now().Unix()),
		600,
		ENCRYPTED_LEASESET_FLAG_OFFLINE_KEYS,
		&offSig,
		encTestInnerData(),
		transientPriv,
	)
	require.NoError(t, err, "attacker can construct the structure locally")
	require.True(t, els.HasOfflineKeys())

	err = els.Verify()
	assert.Error(t, err, "Verify must reject a forged offline signature")
	assert.Contains(t, err.Error(), "offline signature")
}

// TestVerifyRejectsOfflineSignatureSignedByWrongKey covers the variant where
// the offline signature is well-formed but produced by a different key than the
// blinded public key in the structure.
func TestVerifyRejectsOfflineSignatureSignedByWrongKey(t *testing.T) {
	blindedPub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	// Attacker's own key pair, unrelated to blindedPub.
	_, attackerPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	transientPub, transientPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	offSig, err := offline_signature.CreateOfflineSignature(
		uint32(time.Now().Add(24*time.Hour).Unix()),
		key_certificate.KEYCERT_SIGN_ED25519,
		transientPub,
		attackerPriv,
		key_certificate.KEYCERT_SIGN_ED25519,
	)
	require.NoError(t, err)

	els, err := NewEncryptedLeaseSet(
		uint16(key_certificate.KEYCERT_SIGN_ED25519),
		blindedPub,
		uint32(time.Now().Unix()),
		600,
		ENCRYPTED_LEASESET_FLAG_OFFLINE_KEYS,
		&offSig,
		encTestInnerData(),
		transientPriv,
	)
	require.NoError(t, err)

	err = els.Verify()
	assert.Error(t, err, "Verify must reject an offline signature not made by the blinded key")
	assert.Contains(t, err.Error(), "offline signature")
}

// TestVerifyAcceptsValidOfflineSignatureByBlindedKey guards against
// over-rejection: a transient key authorized by the blinded key must still
// verify.
func TestVerifyAcceptsValidOfflineSignatureByBlindedKey(t *testing.T) {
	blindedPub, blindedPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	transientPub, transientPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	offSig, err := offline_signature.CreateOfflineSignature(
		uint32(time.Now().Add(24*time.Hour).Unix()),
		key_certificate.KEYCERT_SIGN_ED25519,
		transientPub,
		blindedPriv,
		key_certificate.KEYCERT_SIGN_ED25519,
	)
	require.NoError(t, err)

	els, err := NewEncryptedLeaseSet(
		uint16(key_certificate.KEYCERT_SIGN_ED25519),
		blindedPub,
		uint32(time.Now().Unix()),
		600,
		ENCRYPTED_LEASESET_FLAG_OFFLINE_KEYS,
		&offSig,
		encTestInnerData(),
		transientPriv,
	)
	require.NoError(t, err)

	assert.NoError(t, els.Verify(), "valid offline signature chain must verify")
}

// TestVerifyRejectsExpiredOfflineSignature enforces the transient-key
// authorization window: a correctly signed but expired offline signature must
// not be accepted.
func TestVerifyRejectsExpiredOfflineSignature(t *testing.T) {
	blindedPub, blindedPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	transientPub, transientPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	offSig, err := offline_signature.CreateOfflineSignature(
		uint32(time.Now().Add(-time.Hour).Unix()),
		key_certificate.KEYCERT_SIGN_ED25519,
		transientPub,
		blindedPriv,
		key_certificate.KEYCERT_SIGN_ED25519,
	)
	require.NoError(t, err)

	els, err := NewEncryptedLeaseSet(
		uint16(key_certificate.KEYCERT_SIGN_ED25519),
		blindedPub,
		uint32(time.Now().Unix()),
		600,
		ENCRYPTED_LEASESET_FLAG_OFFLINE_KEYS,
		&offSig,
		encTestInnerData(),
		transientPriv,
	)
	require.NoError(t, err)

	err = els.Verify()
	assert.Error(t, err, "Verify must reject an expired offline signature")
	assert.Contains(t, err.Error(), "expired")
}

// TestVerifyRoundTripRejectsForgedOfflineSignatureOnParsedBytes runs the
// forgery through the wire path a floodfill uses: serialize, re-parse, verify.
func TestVerifyRoundTripRejectsForgedOfflineSignatureOnParsedBytes(t *testing.T) {
	blindedPub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	transientPub, transientPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	offSig := newForgedEncOfflineSignature(t, transientPub, uint32(time.Now().Add(24*time.Hour).Unix()))

	els, err := NewEncryptedLeaseSet(
		uint16(key_certificate.KEYCERT_SIGN_ED25519),
		blindedPub,
		uint32(time.Now().Unix()),
		600,
		ENCRYPTED_LEASESET_FLAG_OFFLINE_KEYS,
		&offSig,
		encTestInnerData(),
		transientPriv,
	)
	require.NoError(t, err)

	wire, err := els.Bytes()
	require.NoError(t, err)

	parsed, _, err := ReadEncryptedLeaseSet(wire)
	require.NoError(t, err, "the forged structure must still parse (framing is valid)")

	assert.Error(t, parsed.Verify(), "parsed forgery must be rejected on the wire path")
}
