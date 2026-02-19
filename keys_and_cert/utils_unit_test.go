package keys_and_cert

import (
	"crypto/rand"
	"testing"

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
		assert.Contains(t, err.Error(), "unsupported signature key type")
	})

	t.Run("wrong size Ed25519", func(t *testing.T) {
		_, err := constructSigningPublicKey(make([]byte, 64), key_certificate.SIGNATURE_TYPE_ED25519_SHA512)
		require.Error(t, err)
	})
}
