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

// TestDecryptInnerAcceptsOfflineSigAuthorizedByBlindedKey is the CM-001
// regression: a spec-valid blinded ELS whose offline signature is authorized by
// the blinded public key A' (NOT the inner unblinded destination key A) must
// both Verify() and decrypt successfully.
//
// Before the fix, the decrypt path re-checked the offline signature against the
// decrypted inner destination's signing key (the unblinded A), which never
// matches the blinded A' that actually authorized the transient key. Every
// spec-valid blinded ELS therefore failed decryption and the destination never
// resolved, even though Verify() passed. i2pd (LeaseSet.cpp) and the Java
// implementation both verify with the blinded A'.
func TestDecryptInnerAcceptsOfflineSigAuthorizedByBlindedKey(t *testing.T) {
	// Blinded identity A' that authorizes the transient key.
	blindedPub, blindedPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	// Transient key that signs the published ELS.
	transientPub, transientPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	// Offline signature: transient key authorized by the BLINDED key A'.
	offSig, err := offline_signature.CreateOfflineSignature(
		uint32(time.Now().Add(24*time.Hour).Unix()),
		key_certificate.KEYCERT_SIGN_ED25519,
		transientPub,
		blindedPriv,
		key_certificate.KEYCERT_SIGN_ED25519,
	)
	require.NoError(t, err)

	// Inner LeaseSet2 carries the real (unblinded) destination key A, which is
	// unrelated to A' or the transient key — exactly the blinded-destination case.
	ls2 := createTestLeaseSet2ForEncryption(t)
	var subcredential [32]byte
	_, err = rand.Read(subcredential[:])
	require.NoError(t, err)
	published := uint32(time.Now().Unix())

	encrypted, err := EncryptInnerLeaseSet2(ls2, subcredential, published)
	require.NoError(t, err)

	els, err := NewEncryptedLeaseSet(
		uint16(key_certificate.KEYCERT_SIGN_ED25519),
		blindedPub,
		published,
		600,
		ENCRYPTED_LEASESET_FLAG_OFFLINE_KEYS,
		&offSig,
		encrypted,
		transientPriv,
	)
	require.NoError(t, err)

	// Verify() already accepted this structure (offline chain against blinded key).
	require.NoError(t, els.Verify(), "spec-valid blinded ELS must verify")

	// CM-001: the decrypt path must also accept it, checking the offline
	// signature against the blinded key rather than the inner destination key.
	decrypted, err := els.DecryptInnerData(subcredential)
	require.NoError(t, err, "decrypt must accept offline sig authorized by blinded key A'")
	require.NotNil(t, decrypted)
	assert.Equal(t, ls2.Published(), decrypted.Published())
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
