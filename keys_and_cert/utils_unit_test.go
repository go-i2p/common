package keys_and_cert

import (
	"testing"

	"github.com/go-i2p/crypto/rand"

	"github.com/go-i2p/common/key_certificate"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============================================================================
// constructPublicKey
// ============================================================================

func TestConstructPublicKey_X25519(t *testing.T) {
	t.Run("valid X25519 key", func(t *testing.T) {
		keyData := make([]byte, 32)
		_, err := rand.Read(keyData)
		require.NoError(t, err)
		pubKey, err := constructPublicKey(keyData, key_certificate.KEYCERT_CRYPTO_X25519)
		require.NoError(t, err)
		assert.NotNil(t, pubKey)
		assert.Equal(t, 32, pubKey.Len())
		assert.Equal(t, keyData, pubKey.Bytes())
	})

	t.Run("wrong size X25519", func(t *testing.T) {
		_, err := constructPublicKey(make([]byte, 64), key_certificate.KEYCERT_CRYPTO_X25519)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid X25519 public key length")
	})

	t.Run("ElGamal still works", func(t *testing.T) {
		keyData := make([]byte, 256)
		pubKey, err := constructPublicKey(keyData, key_certificate.CRYPTO_KEY_TYPE_ELGAMAL)
		require.NoError(t, err)
		assert.Equal(t, 256, pubKey.Len())
	})

	t.Run("unsupported type returns error", func(t *testing.T) {
		_, err := constructPublicKey(make([]byte, 96), 99)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported crypto key type")
	})
}

// ============================================================================
// constructSigningPublicKey
// ============================================================================

func TestConstructSigningPublicKey_ModernTypes(t *testing.T) {
	keyData := make([]byte, 32)
	_, err := rand.Read(keyData)
	require.NoError(t, err)

	t.Run("Ed25519", func(t *testing.T) {
		key, err := constructSigningPublicKey(keyData, key_certificate.SIGNATURE_TYPE_ED25519_SHA512)
		require.NoError(t, err)
		assert.Equal(t, 32, key.Len())
	})

	t.Run("Ed25519ph", func(t *testing.T) {
		key, err := constructSigningPublicKey(keyData, key_certificate.KEYCERT_SIGN_ED25519PH)
		require.NoError(t, err)
		assert.Equal(t, 32, key.Len())
	})

	t.Run("RedDSA", func(t *testing.T) {
		key, err := constructSigningPublicKey(keyData, key_certificate.KEYCERT_SIGN_REDDSA_ED25519)
		require.NoError(t, err)
		assert.Equal(t, 32, key.Len())
	})

	t.Run("unsupported type", func(t *testing.T) {
		_, err := constructSigningPublicKey(keyData, 99)
		require.Error(t, err)
		// key_certificate.ConstructSigningPublicKeyByType returns "unknown signing key type"
		assert.Contains(t, err.Error(), "unknown signing key type")
	})

	t.Run("wrong size Ed25519 (too small)", func(t *testing.T) {
		// < 32 bytes is always insufficient for Ed25519
		_, err := constructSigningPublicKey(make([]byte, 8), key_certificate.SIGNATURE_TYPE_ED25519_SHA512)
		require.Error(t, err)
	})

	t.Run("DSA-SHA1 returns legacy error", func(t *testing.T) {
		_, err := constructSigningPublicKey(make([]byte, 128), 0)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "legacy")
	})

	t.Run("ECDSA-P256 succeeds", func(t *testing.T) {
		key, err := constructSigningPublicKey(make([]byte, 64), 1)
		require.NoError(t, err)
		assert.NotNil(t, key)
		assert.Equal(t, 64, key.Len())
	})

	t.Run("ECDSA-P384 succeeds", func(t *testing.T) {
		key, err := constructSigningPublicKey(make([]byte, 96), 2)
		require.NoError(t, err)
		assert.NotNil(t, key)
		assert.Equal(t, 96, key.Len())
	})
}

// ============================================================================
// constructPublicKey — unsupported crypto type error paths
// ============================================================================

func TestConstructPublicKey_UnsupportedCryptoTypes(t *testing.T) {
	t.Run("P256 returns unsupported", func(t *testing.T) {
		_, err := constructPublicKey(make([]byte, 64), 1)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported crypto key type: 1")
	})

	t.Run("P384 returns unsupported", func(t *testing.T) {
		_, err := constructPublicKey(make([]byte, 96), 2)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported crypto key type: 2")
	})

	t.Run("P521 returns unsupported", func(t *testing.T) {
		_, err := constructPublicKey(make([]byte, 132), 3)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported crypto key type: 3")
	})
}
