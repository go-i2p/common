package key_certificate

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRoundTripSerialization verifies that creating a KeyCertificate with
// NewKeyCertificateWithTypes, serializing with Data(), and re-parsing with
// NewKeyCertificate produces an equivalent certificate.
func TestRoundTripSerialization(t *testing.T) {
	tests := []struct {
		name        string
		signingType int
		cryptoType  int
	}{
		{"Ed25519_X25519", KEYCERT_SIGN_ED25519, KEYCERT_CRYPTO_X25519},
		{"DSA_ElGamal", KEYCERT_SIGN_DSA_SHA1, KEYCERT_CRYPTO_ELG},
		{"P256_ElGamal", KEYCERT_SIGN_P256, KEYCERT_CRYPTO_ELG},
		{"P384_ElGamal", KEYCERT_SIGN_P384, KEYCERT_CRYPTO_ELG},
		{"RedDSA_X25519", KEYCERT_SIGN_REDDSA_ED25519, KEYCERT_CRYPTO_X25519},
		{"Ed25519ph_X25519", KEYCERT_SIGN_ED25519PH, KEYCERT_CRYPTO_X25519},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			original, err := NewKeyCertificateWithTypes(tt.signingType, tt.cryptoType)
			require.NoError(t, err)

			rawData := original.Certificate.RawBytes()
			require.NotEmpty(t, rawData, "RawBytes() should return non-empty data")

			certBytes := original.Certificate.Bytes()
			require.NotEmpty(t, certBytes, "Bytes() should return non-empty data")

			reparsed, _, err := NewKeyCertificate(certBytes)
			require.NoError(t, err)
			require.NotNil(t, reparsed)

			assert.Equal(t, tt.signingType, reparsed.SigningPublicKeyType(),
				"Round-trip should preserve signing type")
			assert.Equal(t, tt.cryptoType, reparsed.PublicKeyType(),
				"Round-trip should preserve crypto type")
			assert.Equal(t, original.SigningPublicKeySize(), reparsed.SigningPublicKeySize(),
				"Round-trip should preserve signing key size")
			assert.Equal(t, original.CryptoSize(), reparsed.CryptoSize(),
				"Round-trip should preserve crypto size")
			assert.Equal(t, original.SignatureSize(), reparsed.SignatureSize(),
				"Round-trip should preserve signature size")
		})
	}
}

// TestSignatureSize_ConsistentWithGetSignatureSize verifies that the method
// and the standalone function return identical values for all key types.
func TestSignatureSize_ConsistentWithGetSignatureSize(t *testing.T) {
	for _, sigType := range testAllSigningTypes {
		keyCert, err := NewKeyCertificateWithTypes(sigType, KEYCERT_CRYPTO_X25519)
		require.NoError(t, err)

		methodSize := keyCert.SignatureSize()
		funcSize, err := GetSignatureSize(sigType)
		require.NoError(t, err)

		assert.Equal(t, funcSize, methodSize,
			"SignatureSize() method and GetSignatureSize() function should return same value for type %d", sigType)
	}
}

// TestSigningPublicKeySize_ConsistentWithSigningKeySizes verifies the method
// returns the same values as the canonical SigningKeySizes map.
func TestSigningPublicKeySize_ConsistentWithSigningKeySizes(t *testing.T) {
	for sigType, info := range SigningKeySizes {
		keyCert, err := NewKeyCertificateWithTypes(sigType, KEYCERT_CRYPTO_X25519)
		require.NoError(t, err)

		size := keyCert.SigningPublicKeySize()
		assert.Equal(t, info.SigningPublicKeySize, size,
			"SigningPublicKeySize() should match SigningKeySizes map for type %d", sigType)
	}
}
