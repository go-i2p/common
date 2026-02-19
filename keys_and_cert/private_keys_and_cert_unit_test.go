package keys_and_cert

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============================================================================
// PrivateKeysAndCert – nil receiver
// ============================================================================

func TestPrivateKeysAndCert(t *testing.T) {
	t.Run("nil returns nil keys", func(t *testing.T) {
		var pkac *PrivateKeysAndCert
		assert.Nil(t, pkac.PrivateKey())
		assert.Nil(t, pkac.SigningPrivateKey())
	})

	t.Run("Validate nil struct", func(t *testing.T) {
		var pkac *PrivateKeysAndCert
		err := pkac.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "PrivateKeysAndCert is nil")
	})

	t.Run("Validate missing private key", func(t *testing.T) {
		kac := createValidKeyAndCert(t)
		pkac := &PrivateKeysAndCert{
			KeysAndCert: *kac,
			PK_KEY:      nil,
			SPK_KEY:     []byte("test-spk"),
		}
		err := pkac.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "encryption private key")
	})

	t.Run("Validate missing signing private key", func(t *testing.T) {
		kac := createValidKeyAndCert(t)
		pkac := &PrivateKeysAndCert{
			KeysAndCert: *kac,
			PK_KEY:      []byte("test-pk"),
			SPK_KEY:     nil,
		}
		err := pkac.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "signing private key")
	})

	t.Run("Validate valid struct", func(t *testing.T) {
		kac := createValidKeyAndCert(t)
		pkac := &PrivateKeysAndCert{
			KeysAndCert: *kac,
			PK_KEY:      []byte("test-pk"),
			SPK_KEY:     []byte("test-spk"),
		}
		err := pkac.Validate()
		require.NoError(t, err)
	})

	t.Run("accessor methods return correct values", func(t *testing.T) {
		kac := createValidKeyAndCert(t)
		pkData := []byte("test-private-key")
		spkData := []byte("test-signing-key")
		pkac := &PrivateKeysAndCert{
			KeysAndCert: *kac,
			PK_KEY:      pkData,
			SPK_KEY:     spkData,
		}
		assert.Equal(t, pkData, pkac.PrivateKey().([]byte))
		assert.Equal(t, spkData, pkac.SigningPrivateKey().([]byte))
	})
}

// ============================================================================
// PrivateKeysAndCert – direct construction
// ============================================================================

func TestPrivateKeysAndCertConstruction(t *testing.T) {
	kac := createValidKeyAndCert(t)
	pkac := PrivateKeysAndCert{
		KeysAndCert: *kac,
		PK_KEY:      []byte("encryption-private-key"),
		SPK_KEY:     []byte("signing-private-key"),
	}

	assert.NotNil(t, pkac.PK_KEY)
	assert.NotNil(t, pkac.SPK_KEY)
	assert.True(t, pkac.KeysAndCert.IsValid())
}

// ============================================================================
// NewPrivateKeysAndCert constructor
// ============================================================================

func TestNewPrivateKeysAndCert(t *testing.T) {
	t.Run("creates valid struct with all fields", func(t *testing.T) {
		kac := createValidKeyAndCert(t)
		encPriv := []byte("encryption-private-key")
		sigPriv := []byte("signing-private-key")
		pkac, err := NewPrivateKeysAndCert(
			kac.KeyCertificate,
			kac.ReceivingPublic,
			kac.Padding,
			kac.SigningPublic,
			encPriv,
			sigPriv,
		)
		require.NoError(t, err)
		assert.NotNil(t, pkac)
		assert.Equal(t, encPriv, pkac.PrivateKey().([]byte))
		assert.Equal(t, sigPriv, pkac.SigningPrivateKey().([]byte))
		assert.True(t, pkac.KeysAndCert.IsValid())
	})

	t.Run("rejects nil encryption private key", func(t *testing.T) {
		kac := createValidKeyAndCert(t)
		_, err := NewPrivateKeysAndCert(
			kac.KeyCertificate,
			kac.ReceivingPublic,
			kac.Padding,
			kac.SigningPublic,
			nil,
			[]byte("signing-key"),
		)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "encryption private key")
	})

	t.Run("rejects nil signing private key", func(t *testing.T) {
		kac := createValidKeyAndCert(t)
		_, err := NewPrivateKeysAndCert(
			kac.KeyCertificate,
			kac.ReceivingPublic,
			kac.Padding,
			kac.SigningPublic,
			[]byte("enc-key"),
			nil,
		)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "signing private key")
	})

	t.Run("rejects nil key certificate", func(t *testing.T) {
		_, err := NewPrivateKeysAndCert(
			nil,
			createDummyReceivingKey(),
			make([]byte, 96),
			createDummySigningKey(),
			[]byte("enc-key"),
			[]byte("sig-key"),
		)
		require.Error(t, err)
	})
}
