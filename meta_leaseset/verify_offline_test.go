package meta_leaseset

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/destination"
	"github.com/go-i2p/common/key_certificate"
	"github.com/go-i2p/common/offline_signature"
	sigpkg "github.com/go-i2p/common/signature"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Regression tests for the MetaLeaseSet offline-signature bypass.
//
// Before the fix, Verify() resolved the transient signing key straight out of
// the OfflineSignature whenever the offline-keys flag was set, without ever
// checking that the destination's long-term key had signed that transient key.
// Anyone could therefore pick a transient key, put random bytes in the offline
// signature field, sign the MetaLeaseSet with the chosen key, and have it
// verify as the victim destination.

// createMetaDestWithKey builds a destination with the given Ed25519 public key
// in the signing key field so signature verification uses it.
func createMetaDestWithKey(t *testing.T, pubKey ed25519.PublicKey) destination.Destination {
	t.Helper()
	keysData := make([]byte, 384)
	copy(keysData[352:384], pubKey)

	certData := []byte{
		0x05,       // Certificate type = KEY (5)
		0x00, 0x04, // Certificate length = 4 bytes
		0x00, 0x07, // Signing key type = Ed25519 (7)
		0x00, 0x04, // Crypto key type = X25519 (4)
	}

	dest, _, err := destination.ReadDestination(append(keysData, certData...))
	require.NoError(t, err)
	return dest
}

// newForgedOfflineSignature builds an OfflineSignature that the destination's
// long-term key never signed: the signature field is random bytes.
func newForgedOfflineSignature(t *testing.T, transientPub ed25519.PublicKey, expires uint32) offline_signature.OfflineSignature {
	t.Helper()
	forgedSigBytes := make([]byte, sigpkg.EdDSA_SHA512_Ed25519_SIZE)
	_, err := rand.Read(forgedSigBytes)
	require.NoError(t, err)

	offSig, err := offline_signature.NewOfflineSignature(
		expires,
		uint16(key_certificate.KEYCERT_SIGN_ED25519),
		transientPub,
		forgedSigBytes,
		uint16(key_certificate.KEYCERT_SIGN_ED25519),
	)
	require.NoError(t, err)
	return offSig
}

func testMetaLeaseEntries() []MetaLeaseSetEntry {
	return []MetaLeaseSetEntry{createTestEntryStruct(META_LEASESET_ENTRY_TYPE_LEASESET2, 1)}
}

// TestVerifyRejectsMetaLeaseSetWithForgedOfflineSignature proves the core
// forgery: attacker-chosen transient key + random offline signature bytes +
// outer signature made with the attacker's transient key MUST NOT verify.
func TestVerifyRejectsMetaLeaseSetWithForgedOfflineSignature(t *testing.T) {
	// Victim destination whose identity the attacker wants to impersonate.
	victimPub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	dest := createMetaDestWithKey(t, victimPub)

	// Attacker-controlled transient key pair.
	transientPub, transientPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	offSig := newForgedOfflineSignature(t, transientPub, uint32(time.Now().Add(24*time.Hour).Unix()))

	mls, err := NewMetaLeaseSet(
		dest, uint32(time.Now().Unix()), 600, META_LEASESET_FLAG_OFFLINE_KEYS, &offSig,
		common.Mapping{}, testMetaLeaseEntries(), nil, transientPriv,
	)
	require.NoError(t, err, "attacker can construct the structure locally")
	require.True(t, mls.HasOfflineKeys())

	err = mls.Verify()
	assert.Error(t, err, "Verify must reject a MetaLeaseSet with a forged offline signature")
	assert.Contains(t, err.Error(), "offline signature")
}

// TestVerifyRejectsMetaLeaseSetSignedByWrongOfflineKey covers the variant where
// the offline signature is a well-formed signature but made with some other
// key than the destination's long-term key.
func TestVerifyRejectsMetaLeaseSetSignedByWrongOfflineKey(t *testing.T) {
	victimPub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	dest := createMetaDestWithKey(t, victimPub)

	// Attacker signs the transient key with their OWN key, not the victim's.
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

	mls, err := NewMetaLeaseSet(
		dest, uint32(time.Now().Unix()), 600, META_LEASESET_FLAG_OFFLINE_KEYS, &offSig,
		common.Mapping{}, testMetaLeaseEntries(), nil, transientPriv,
	)
	require.NoError(t, err)

	err = mls.Verify()
	assert.Error(t, err, "Verify must reject an offline signature not made by the destination key")
	assert.Contains(t, err.Error(), "offline signature")
}

// TestVerifyAcceptsMetaLeaseSetWithValidOfflineSignature guards against
// over-rejection: a legitimately authorized transient key must still verify.
func TestVerifyAcceptsMetaLeaseSetWithValidOfflineSignature(t *testing.T) {
	victimPub, victimPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	dest := createMetaDestWithKey(t, victimPub)

	transientPub, transientPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	offSig, err := offline_signature.CreateOfflineSignature(
		uint32(time.Now().Add(24*time.Hour).Unix()),
		key_certificate.KEYCERT_SIGN_ED25519,
		transientPub,
		victimPriv,
		key_certificate.KEYCERT_SIGN_ED25519,
	)
	require.NoError(t, err)

	mls, err := NewMetaLeaseSet(
		dest, uint32(time.Now().Unix()), 600, META_LEASESET_FLAG_OFFLINE_KEYS, &offSig,
		common.Mapping{}, testMetaLeaseEntries(), nil, transientPriv,
	)
	require.NoError(t, err)

	assert.NoError(t, mls.Verify(), "valid offline signature chain must verify")
}

// TestVerifyRejectsExpiredOfflineSignatureMetaLeaseSet enforces the expiry on
// the transient-key authorization: a correctly signed but expired offline
// signature must not be accepted.
func TestVerifyRejectsExpiredOfflineSignatureMetaLeaseSet(t *testing.T) {
	victimPub, victimPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	dest := createMetaDestWithKey(t, victimPub)

	transientPub, transientPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	// Signed by the right key, but expired an hour ago.
	offSig, err := offline_signature.CreateOfflineSignature(
		uint32(time.Now().Add(-time.Hour).Unix()),
		key_certificate.KEYCERT_SIGN_ED25519,
		transientPub,
		victimPriv,
		key_certificate.KEYCERT_SIGN_ED25519,
	)
	require.NoError(t, err)

	mls, err := NewMetaLeaseSet(
		dest, uint32(time.Now().Unix()), 600, META_LEASESET_FLAG_OFFLINE_KEYS, &offSig,
		common.Mapping{}, testMetaLeaseEntries(), nil, transientPriv,
	)
	require.NoError(t, err)

	err = mls.Verify()
	assert.Error(t, err, "Verify must reject an expired offline signature")
	assert.Contains(t, err.Error(), "expired")
}

// TestVerifyRoundTripRejectsForgedOfflineSignatureOnParsedBytes runs the
// forgery through the wire path a floodfill actually uses: serialize, re-parse,
// verify.
func TestVerifyRoundTripRejectsForgedOfflineSignatureOnParsedBytes(t *testing.T) {
	victimPub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	dest := createMetaDestWithKey(t, victimPub)

	transientPub, transientPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	offSig := newForgedOfflineSignature(t, transientPub, uint32(time.Now().Add(24*time.Hour).Unix()))

	mls, err := NewMetaLeaseSet(
		dest, uint32(time.Now().Unix()), 600, META_LEASESET_FLAG_OFFLINE_KEYS, &offSig,
		common.Mapping{}, testMetaLeaseEntries(), nil, transientPriv,
	)
	require.NoError(t, err)

	wire, err := mls.Bytes()
	require.NoError(t, err)

	parsed, _, err := ReadMetaLeaseSet(wire)
	require.NoError(t, err, "the forged structure must still parse (framing is valid)")

	assert.Error(t, parsed.Verify(), "parsed forgery must be rejected on the wire path")
}
