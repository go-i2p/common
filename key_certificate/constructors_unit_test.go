package key_certificate

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewKeyCertificateWithTypes(t *testing.T) {
	tests := []struct {
		name        string
		signingType int
		cryptoType  int
		wantErr     bool
	}{
		{
			name:        "Ed25519_X25519",
			signingType: KEYCERT_SIGN_ED25519,
			cryptoType:  KEYCERT_CRYPTO_X25519,
			wantErr:     false,
		},
		{
			name:        "ECDSA_P256_ElGamal",
			signingType: KEYCERT_SIGN_P256,
			cryptoType:  KEYCERT_CRYPTO_ELG,
			wantErr:     false,
		},
		{
			name:        "DSA_ElGamal",
			signingType: KEYCERT_SIGN_DSA_SHA1,
			cryptoType:  KEYCERT_CRYPTO_ELG,
			wantErr:     false,
		},
		{
			name:        "Invalid_Signing_Type",
			signingType: 9999,
			cryptoType:  KEYCERT_CRYPTO_X25519,
			wantErr:     true,
		},
		{
			name:        "Invalid_Crypto_Type",
			signingType: KEYCERT_SIGN_ED25519,
			cryptoType:  9999,
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyCert, err := NewKeyCertificateWithTypes(tt.signingType, tt.cryptoType)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, keyCert)
			} else {
				require.NoError(t, err)
				require.NotNil(t, keyCert)

				// Verify the key types are set correctly
				assert.Equal(t, tt.signingType, keyCert.SigningPublicKeyType())
				assert.Equal(t, tt.cryptoType, keyCert.PublicKeyType())
			}
		})
	}
}

func TestNewEd25519X25519KeyCertificate(t *testing.T) {
	keyCert, err := NewEd25519X25519KeyCertificate()

	require.NoError(t, err)
	require.NotNil(t, keyCert)

	assert.Equal(t, KEYCERT_SIGN_ED25519, keyCert.SigningPublicKeyType())
	assert.Equal(t, KEYCERT_CRYPTO_X25519, keyCert.PublicKeyType())
}

func TestNewECDSAP256KeyCertificate(t *testing.T) {
	keyCert, err := NewECDSAP256KeyCertificate()

	require.NoError(t, err)
	require.NotNil(t, keyCert)

	assert.Equal(t, KEYCERT_SIGN_P256, keyCert.SigningPublicKeyType())
	assert.Equal(t, KEYCERT_CRYPTO_ELG, keyCert.PublicKeyType())
}

func TestNewECDSAP384KeyCertificate(t *testing.T) {
	keyCert, err := NewECDSAP384KeyCertificate()

	require.NoError(t, err)
	require.NotNil(t, keyCert)

	assert.Equal(t, KEYCERT_SIGN_P384, keyCert.SigningPublicKeyType())
	assert.Equal(t, KEYCERT_CRYPTO_ELG, keyCert.PublicKeyType())
}

func TestNewDSAElGamalKeyCertificate(t *testing.T) {
	keyCert, err := NewDSAElGamalKeyCertificate()

	require.NoError(t, err)
	require.NotNil(t, keyCert)

	assert.Equal(t, KEYCERT_SIGN_DSA_SHA1, keyCert.SigningPublicKeyType())
	assert.Equal(t, KEYCERT_CRYPTO_ELG, keyCert.PublicKeyType())
}

// TestNewDSAElGamalKeyCertificate_DeprecationWarning verifies that the deprecated
// DSA/ElGamal constructor still works but is properly marked as deprecated.
func TestNewDSAElGamalKeyCertificate_DeprecationWarning(t *testing.T) {
	t.Run("still_works_despite_deprecation", func(t *testing.T) {
		keyCert, err := NewDSAElGamalKeyCertificate()

		require.NoError(t, err, "deprecated function should still work for backward compatibility")
		require.NotNil(t, keyCert)

		assert.Equal(t, KEYCERT_SIGN_DSA_SHA1, keyCert.SigningPublicKeyType())
		assert.Equal(t, KEYCERT_CRYPTO_ELG, keyCert.PublicKeyType())
	})

	t.Run("prefer_modern_alternative", func(t *testing.T) {
		modernKeyCert, err := NewEd25519X25519KeyCertificate()

		require.NoError(t, err)
		require.NotNil(t, modernKeyCert)

		assert.Equal(t, KEYCERT_SIGN_ED25519, modernKeyCert.SigningPublicKeyType())
		assert.Equal(t, KEYCERT_CRYPTO_X25519, modernKeyCert.PublicKeyType())

		legacyKeyCert, _ := NewDSAElGamalKeyCertificate()
		assert.NotEqual(t, legacyKeyCert.SigningPublicKeyType(), modernKeyCert.SigningPublicKeyType())
		assert.NotEqual(t, legacyKeyCert.PublicKeyType(), modernKeyCert.PublicKeyType())
	})
}

func TestNewRedDSAX25519KeyCertificate(t *testing.T) {
	keyCert, err := NewRedDSAX25519KeyCertificate()

	require.NoError(t, err)
	require.NotNil(t, keyCert)

	assert.Equal(t, KEYCERT_SIGN_REDDSA_ED25519, keyCert.SigningPublicKeyType())
	assert.Equal(t, KEYCERT_CRYPTO_X25519, keyCert.PublicKeyType())
}

func TestBuildKeyCertificatePayload(t *testing.T) {
	payload := buildKeyCertificatePayload(KEYCERT_SIGN_ED25519, KEYCERT_CRYPTO_X25519)

	assert.Equal(t, 4, len(payload), "Payload should be 4 bytes")
	assert.Equal(t, []byte{0x00, 0x07, 0x00, 0x04}, payload)
}

// TestConstructSigningPublicKeyByType_RawEd25519 verifies Ed25519 construction from raw 32-byte key.
func TestConstructSigningPublicKeyByType_RawEd25519(t *testing.T) {
	rawKey := makeTestBytes(32, 0)

	spk, err := ConstructSigningPublicKeyByType(rawKey, KEYCERT_SIGN_ED25519)
	require.NoError(t, err)
	require.NotNil(t, spk)
	assert.Equal(t, 32, spk.Len())
}

// TestConstructSigningPublicKeyByType_RawP256 verifies P256 construction from raw 64-byte key.
func TestConstructSigningPublicKeyByType_RawP256(t *testing.T) {
	rawKey := makeTestBytes(64, 0)

	spk, err := ConstructSigningPublicKeyByType(rawKey, KEYCERT_SIGN_P256)
	require.NoError(t, err)
	require.NotNil(t, spk)
	assert.Equal(t, KEYCERT_SIGN_P256_SIZE, spk.Len())
}

// TestConstructSigningPublicKeyByType_RawP384 verifies P384 construction from raw 96-byte key.
func TestConstructSigningPublicKeyByType_RawP384(t *testing.T) {
	rawKey := makeTestBytes(96, 0)

	spk, err := ConstructSigningPublicKeyByType(rawKey, KEYCERT_SIGN_P384)
	require.NoError(t, err)
	require.NotNil(t, spk)
	assert.Equal(t, KEYCERT_SIGN_P384_SIZE, spk.Len())
}

// Benchmark tests
func BenchmarkNewEd25519X25519KeyCertificate(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = NewEd25519X25519KeyCertificate()
	}
}

func BenchmarkNewKeyCertificateWithTypes(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = NewKeyCertificateWithTypes(KEYCERT_SIGN_ED25519, KEYCERT_CRYPTO_X25519)
	}
}
