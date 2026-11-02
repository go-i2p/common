// Tests for blinded EncryptedLeaseSet signing: the constructor must refuse a
// signing key that does not correspond to the blinded public key the structure
// publishes, and CreateBlindedDestinationWithPrivateKey must produce a matching
// (A', a') pair from one alpha.
package encrypted_leaseset

import (
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/go-i2p/common/key_certificate"
	goi2ped25519 "github.com/go-i2p/crypto/ed25519"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCreateBlindedDestinationWithPrivateKeyPairing asserts the blinded
// destination and the blinded scalar are one key pair. If they came from
// different alphas, every EncryptedLeaseSet the router publishes fails
// verification at a spec-following floodfill.
func TestCreateBlindedDestinationWithPrivateKeyPairing(t *testing.T) {
	dest := createTestEd25519Destination(t)
	secret := []byte("pairing-secret")
	date := time.Date(2026, 3, 4, 0, 0, 0, 0, time.UTC)

	// The blinded scalar needs the destination's private signing key, so build a
	// destination around a key pair we hold.
	signingPub, signingPriv, err := goi2ped25519.GenerateEd25519KeyPair()
	require.NoError(t, err)
	dest = createTestEd25519KeyedDestination(t, signingPub.Bytes())

	blindedDest, blindedPriv, err := CreateBlindedDestinationWithPrivateKey(
		dest, signingPriv.Bytes(), secret, date)
	require.NoError(t, err)

	blindedSPK, err := blindedDest.SigningPublicKey()
	require.NoError(t, err)

	// a'.public must equal A' exactly.
	derived, err := blindedPriv.Public()
	require.NoError(t, err)
	assert.Equal(t, blindedSPK.Bytes(), derived.Bytes(),
		"blinded scalar a' must correspond to the blinded public key A'")

	// The blinded destination declares RedDSA (11), per spec.
	assert.Equal(t, key_certificate.KEYCERT_SIGN_REDDSA_ED25519,
		blindedDest.KeyCertificate.SigningPublicKeyType())

	// The blinded key must differ from the destination's own key, or blinding
	// would be a no-op that leaks the destination.
	assert.NotEqual(t, signingPub.Bytes(), blindedSPK.Bytes(),
		"blinded key must not equal the destination signing key")

	// Same secret + date must reproduce the same blinded key pair (rotation is
	// by date, not random).
	again, againPriv, err := CreateBlindedDestinationWithPrivateKey(
		dest, signingPriv.Bytes(), secret, date)
	require.NoError(t, err)
	againSPK, err := again.SigningPublicKey()
	require.NoError(t, err)
	assert.Equal(t, blindedSPK.Bytes(), againSPK.Bytes(), "same date must yield the same blinded key")
	assert.Equal(t, blindedPriv, againPriv, "same date must yield the same blinded scalar")

	// A different date must rotate to a different key pair.
	nextDay, nextPriv, err := CreateBlindedDestinationWithPrivateKey(
		dest, signingPriv.Bytes(), secret, date.AddDate(0, 0, 1))
	require.NoError(t, err)
	nextSPK, err := nextDay.SigningPublicKey()
	require.NoError(t, err)
	assert.NotEqual(t, blindedSPK.Bytes(), nextSPK.Bytes(), "date rotation must change the blinded key")
	assert.NotEqual(t, blindedPriv, nextPriv, "date rotation must change the blinded scalar")
}

// TestNewEncryptedLeaseSetRejectsUnblindedSigningKey is the library half of the
// deanonymization finding: previously the constructor accepted the destination's
// long-term signing key alongside an unrelated blinded public key, so a router
// could publish a structure that verifies under the unblinded destination key.
func TestNewEncryptedLeaseSetRejectsUnblindedSigningKey(t *testing.T) {
	_, encryptedData, _, published := createTestEncryptionContext(t)

	// Destination key pair.
	destPub, destPriv, err := goi2ped25519.GenerateEd25519KeyPair()
	require.NoError(t, err)
	dest := createTestEd25519KeyedDestination(t, destPub.Bytes())

	// A genuinely blinded key pair (A', a') for that destination.
	date := time.Unix(int64(published), 0).UTC()
	blindedDest, blindedPriv, err := CreateBlindedDestinationWithPrivateKey(
		dest, destPriv.Bytes(), []byte("reject-secret"), date)
	require.NoError(t, err)
	blindedSPK, err := blindedDest.SigningPublicKey()
	require.NoError(t, err)

	// Signing the blinded-key structure with the UNBLINDED destination key must
	// be refused outright.
	_, err = NewEncryptedLeaseSet(
		key_certificate.KEYCERT_SIGN_REDDSA_ED25519,
		blindedSPK.Bytes(),
		published,
		600,
		0,
		nil,
		encryptedData,
		destPriv.Bytes(),
	)
	require.Error(t, err, "unblinded signing key must not be accepted for a blinded public key")
	assert.Contains(t, err.Error(), "does not correspond", "error should explain the key mismatch")

	// The matching blinded scalar must be accepted.
	els, err := NewEncryptedLeaseSet(
		key_certificate.KEYCERT_SIGN_REDDSA_ED25519,
		blindedSPK.Bytes(),
		published,
		600,
		0,
		nil,
		encryptedData,
		blindedPriv,
	)
	require.NoError(t, err, "blinded scalar must be accepted")
	require.NoError(t, els.Verify(), "a correctly blinded EncryptedLeaseSet must verify")
}

// TestNewEncryptedLeaseSetRejectsForeignKeyPair asserts a valid key pair that
// simply belongs to a different destination is rejected too: the check is key
// identity, not key well-formedness.
func TestNewEncryptedLeaseSetRejectsForeignKeyPair(t *testing.T) {
	_, encryptedData, _, published := createTestEncryptionContext(t)

	ownerPub, _, err := goi2ped25519.GenerateEd25519KeyPair()
	require.NoError(t, err)
	_, otherPriv, err := goi2ped25519.GenerateEd25519KeyPair()
	require.NoError(t, err)

	_, err = NewEncryptedLeaseSet(
		key_certificate.KEYCERT_SIGN_ED25519,
		ownerPub.Bytes(),
		published,
		600,
		0,
		nil,
		encryptedData,
		otherPriv.Bytes(),
	)
	require.Error(t, err, "an unrelated private key must not sign for this public key")
}

// TestNewEncryptedLeaseSetOfflineKeysChecksTransientKey pins that the guard
// compares against the key Verify() will actually use: when offline keys are
// present, that is the transient key, not the blinded key.
func TestNewEncryptedLeaseSetOfflineKeysChecksTransientKey(t *testing.T) {
	_, encryptedData, _, published := createTestEncryptionContext(t)

	destPub, destPriv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	transientPub, transientPriv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	offlineSig := buildOfflineSignature(t, destPriv, transientPub)

	// The transient key signs, so the record builds and verifies.
	els, err := NewEncryptedLeaseSet(
		key_certificate.KEYCERT_SIGN_ED25519,
		destPub,
		published,
		600,
		ENCRYPTED_LEASESET_FLAG_OFFLINE_KEYS,
		&offlineSig,
		encryptedData,
		transientPriv,
	)
	require.NoError(t, err, "transient key must be accepted when it is the verifying key")
	require.NoError(t, els.Verify())

	// The destination's long-term key must NOT be accepted in place of the
	// transient key, since Verify() looks for the transient one.
	_, err = NewEncryptedLeaseSet(
		key_certificate.KEYCERT_SIGN_ED25519,
		destPub,
		published,
		600,
		ENCRYPTED_LEASESET_FLAG_OFFLINE_KEYS,
		&offlineSig,
		encryptedData,
		destPriv,
	)
	require.Error(t, err, "long-term key must not sign in place of the transient key")
}

// TestNewEncryptedLeaseSetFromDestinationBlindedPair exercises the documented
// publishing path: CreateBlindedDestinationWithPrivateKey feeds
// NewEncryptedLeaseSetFromDestination, which extracts A' from the destination.
func TestNewEncryptedLeaseSetFromDestinationBlindedPair(t *testing.T) {
	_, encryptedData, _, published := createTestEncryptionContext(t)

	destPub, destPriv, err := goi2ped25519.GenerateEd25519KeyPair()
	require.NoError(t, err)
	dest := createTestEd25519KeyedDestination(t, destPub.Bytes())

	blindedDest, blindedPriv, err := CreateBlindedDestinationWithPrivateKey(
		dest, destPriv.Bytes(), []byte("doc-path-secret"), time.Unix(int64(published), 0).UTC())
	require.NoError(t, err)

	els, err := NewEncryptedLeaseSetFromDestination(
		blindedDest, published, 600, 0, nil, encryptedData, blindedPriv)
	require.NoError(t, err)
	require.NoError(t, els.Verify(), "record from the documented path must verify")

	// The published blinded key is A', not the destination's encryption key.
	blindedSPK, err := blindedDest.SigningPublicKey()
	require.NoError(t, err)
	require.Equal(t, blindedSPK.Bytes(), els.BlindedPublicKey())
	require.Equal(t, uint16(key_certificate.KEYCERT_SIGN_REDDSA_ED25519), els.SigType())
}
