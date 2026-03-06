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
			SPK_KEY:     createMockSigningPrivateKey(),
		}
		err := pkac.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "encryption private key")
	})

	t.Run("Validate missing signing private key", func(t *testing.T) {
		kac := createValidKeyAndCert(t)
		pkac := &PrivateKeysAndCert{
			KeysAndCert: *kac,
			PK_KEY:      createMockPrivateEncryptionKey(),
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
			PK_KEY:      createMockPrivateEncryptionKey(),
			SPK_KEY:     createMockSigningPrivateKey(),
		}
		err := pkac.Validate()
		require.NoError(t, err)
	})

	t.Run("accessor methods return correct values", func(t *testing.T) {
		kac := createValidKeyAndCert(t)
		encKey := createMockPrivateEncryptionKey()
		sigKey := createMockSigningPrivateKey()
		pkac := &PrivateKeysAndCert{
			KeysAndCert: *kac,
			PK_KEY:      encKey,
			SPK_KEY:     sigKey,
		}
		assert.Equal(t, encKey, pkac.PrivateKey())
		assert.Equal(t, sigKey, pkac.SigningPrivateKey())
	})
}

// ============================================================================
// PrivateKeysAndCert – direct construction
// ============================================================================

func TestPrivateKeysAndCertConstruction(t *testing.T) {
	kac := createValidKeyAndCert(t)
	pkac := PrivateKeysAndCert{
		KeysAndCert: *kac,
		PK_KEY:      createMockPrivateEncryptionKey(),
		SPK_KEY:     createMockSigningPrivateKey(),
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
		encPriv := createMockPrivateEncryptionKey()
		sigPriv := createMockSigningPrivateKey()
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
		assert.Equal(t, encPriv, pkac.PrivateKey())
		assert.Equal(t, sigPriv, pkac.SigningPrivateKey())
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
			createMockSigningPrivateKey(),
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
			createMockPrivateEncryptionKey(),
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
			createMockPrivateEncryptionKey(),
			createMockSigningPrivateKey(),
		)
		require.Error(t, err)
	})
}
