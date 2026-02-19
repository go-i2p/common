package encrypted_leaseset

import (
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/go-i2p/common/key_certificate"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ————————————————————————————————————————————————
// Unit tests for Verify and signingPublicKeyForVerification
// Source: verify.go
// ————————————————————————————————————————————————

func TestVerifyEncryptedLeaseSet(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	encData := make([]byte, 80)
	for i := range encData {
		encData[i] = byte(i)
	}

	els, err := NewEncryptedLeaseSet(
		uint16(key_certificate.KEYCERT_SIGN_ED25519),
		pub,
		uint32(time.Now().Unix()),
		600,
		0,
		nil,
		encData,
		priv,
	)
	require.NoError(t, err)

	t.Run("valid signature passes verification", func(t *testing.T) {
		err := els.Verify()
		assert.NoError(t, err)
	})

	t.Run("corrupted signature fails verification", func(t *testing.T) {
		serialized, err := els.Bytes()
		require.NoError(t, err)

		serialized[len(serialized)-1] ^= 0xFF

		corrupted, _, err := ReadEncryptedLeaseSet(serialized)
		require.NoError(t, err)

		err = corrupted.Verify()
		assert.Error(t, err, "corrupted signature should fail verification")
		assert.Contains(t, err.Error(), "signature verification failed")
	})

	t.Run("corrupted data fails verification", func(t *testing.T) {
		serialized, err := els.Bytes()
		require.NoError(t, err)

		serialized[10] ^= 0xFF

		corrupted, _, err := ReadEncryptedLeaseSet(serialized)
		require.NoError(t, err)

		err = corrupted.Verify()
		assert.Error(t, err, "corrupted content should fail verification")
	})
}

func TestOfflineSignatureParsingPath(t *testing.T) {
	destPub, destPriv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	transientPub, transientPriv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	offlineSig := buildOfflineSignature(t, destPriv, transientPub)

	encData := make([]byte, 80)
	for i := range encData {
		encData[i] = byte(i)
	}

	els, err := NewEncryptedLeaseSet(
		uint16(key_certificate.KEYCERT_SIGN_ED25519),
		destPub,
		uint32(time.Now().Unix()),
		600,
		ENCRYPTED_LEASESET_FLAG_OFFLINE_KEYS,
		&offlineSig,
		encData,
		transientPriv,
	)
	require.NoError(t, err)

	t.Run("has offline keys flag", func(t *testing.T) {
		assert.True(t, els.HasOfflineKeys())
	})

	t.Run("offline signature is present", func(t *testing.T) {
		assert.NotNil(t, els.OfflineSignature())
	})

	t.Run("round-trip preserves offline signature", func(t *testing.T) {
		serialized, err := els.Bytes()
		require.NoError(t, err)

		parsed, _, err := ReadEncryptedLeaseSet(serialized)
		require.NoError(t, err)

		assert.True(t, parsed.HasOfflineKeys())
		assert.NotNil(t, parsed.OfflineSignature())
		assert.Equal(t, els.InnerLength(), parsed.InnerLength())
		assert.Equal(t, els.EncryptedInnerData(), parsed.EncryptedInnerData())
	})

	t.Run("verify uses transient key", func(t *testing.T) {
		err := els.Verify()
		assert.NoError(t, err, "Verify should use the transient key from the offline signature")
	})
}

func TestSigningPublicKeyForVerificationOffline(t *testing.T) {
	destPub, destPriv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	transientPub, transientPriv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	offlineSig := buildOfflineSignature(t, destPriv, transientPub)

	encData := make([]byte, 80)
	els, err := NewEncryptedLeaseSet(
		uint16(key_certificate.KEYCERT_SIGN_ED25519),
		destPub,
		uint32(time.Now().Unix()),
		600,
		ENCRYPTED_LEASESET_FLAG_OFFLINE_KEYS,
		&offlineSig,
		encData,
		transientPriv,
	)
	require.NoError(t, err)

	t.Run("returns transient key when offline keys present", func(t *testing.T) {
		spk, err := els.signingPublicKeyForVerification()
		require.NoError(t, err)

		assert.Equal(t, []byte(transientPub), spk.Bytes(),
			"signingPublicKeyForVerification should return the transient key")
	})

	t.Run("returns blinded key when no offline keys", func(t *testing.T) {
		noOfflineELS, err := NewEncryptedLeaseSet(
			uint16(key_certificate.KEYCERT_SIGN_ED25519),
			destPub,
			uint32(time.Now().Unix()),
			600,
			0,
			nil,
			encData,
			destPriv,
		)
		require.NoError(t, err)

		spk, err := noOfflineELS.signingPublicKeyForVerification()
		require.NoError(t, err)

		assert.Equal(t, []byte(destPub), spk.Bytes(),
			"signingPublicKeyForVerification should return the blinded key")
	})
}

// TestEd25519SigningMatchesCryptoLibrary verifies that createSignature produces
// signatures compatible with the go-i2p/crypto Ed25519Verifier.Verify() method.
func TestEd25519SigningMatchesCryptoLibrary(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	encData := make([]byte, 80)
	els, err := NewEncryptedLeaseSet(
		uint16(key_certificate.KEYCERT_SIGN_ED25519),
		pub,
		uint32(time.Now().Unix()),
		600,
		0,
		nil,
		encData,
		priv,
	)
	require.NoError(t, err)

	dataToVerify, err := els.dataForSigning()
	require.NoError(t, err)

	assert.True(t, ed25519.Verify(pub, dataToVerify, els.Signature().Bytes()),
		"signature must be valid under standard Ed25519 (createSignature signs raw data)")

	err = els.Verify()
	assert.NoError(t, err, "Verify() round-trip must succeed")
}
