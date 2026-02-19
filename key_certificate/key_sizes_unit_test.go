package key_certificate

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetKeySizes(t *testing.T) {
	tests := []struct {
		name                  string
		signingType           int
		cryptoType            int
		wantSignatureSize     int
		wantSigningPubKeySize int
		wantCryptoPubKeySize  int
		wantErr               bool
	}{
		{
			name:                  "Ed25519_X25519",
			signingType:           KEYCERT_SIGN_ED25519,
			cryptoType:            KEYCERT_CRYPTO_X25519,
			wantSignatureSize:     64,
			wantSigningPubKeySize: 32,
			wantCryptoPubKeySize:  32,
			wantErr:               false,
		},
		{
			name:                  "DSA_ElGamal",
			signingType:           KEYCERT_SIGN_DSA_SHA1,
			cryptoType:            KEYCERT_CRYPTO_ELG,
			wantSignatureSize:     40,
			wantSigningPubKeySize: 128,
			wantCryptoPubKeySize:  256,
			wantErr:               false,
		},
		{
			name:                  "P256_P256",
			signingType:           KEYCERT_SIGN_P256,
			cryptoType:            KEYCERT_CRYPTO_P256,
			wantSignatureSize:     64,
			wantSigningPubKeySize: 64,
			wantCryptoPubKeySize:  64,
			wantErr:               false,
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
			sizes, err := GetKeySizes(tt.signingType, tt.cryptoType)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.wantSignatureSize, sizes.SignatureSize)
				assert.Equal(t, tt.wantSigningPubKeySize, sizes.SigningPublicKeySize)
				assert.Equal(t, tt.wantCryptoPubKeySize, sizes.CryptoPublicKeySize)
			}
		})
	}
}

func TestGetSigningKeySize(t *testing.T) {
	tests := []struct {
		name        string
		signingType int
		wantSize    int
		wantErr     bool
	}{
		{"DSA_SHA1", KEYCERT_SIGN_DSA_SHA1, 128, false},
		{"P256", KEYCERT_SIGN_P256, 64, false},
		{"P384", KEYCERT_SIGN_P384, 96, false},
		{"P521", KEYCERT_SIGN_P521, 132, false},
		{"RSA2048", KEYCERT_SIGN_RSA2048, 256, false},
		{"RSA3072", KEYCERT_SIGN_RSA3072, 384, false},
		{"RSA4096", KEYCERT_SIGN_RSA4096, 512, false},
		{"ED25519", KEYCERT_SIGN_ED25519, 32, false},
		{"ED25519PH", KEYCERT_SIGN_ED25519PH, 32, false},
		{"Invalid", 9999, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			size, err := GetSigningKeySize(tt.signingType)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.wantSize, size)
			}
		})
	}
}

func TestGetCryptoKeySize(t *testing.T) {
	tests := []struct {
		name       string
		cryptoType int
		wantSize   int
		wantErr    bool
	}{
		{"ElGamal", KEYCERT_CRYPTO_ELG, 256, false},
		{"P256", KEYCERT_CRYPTO_P256, 64, false},
		{"P384", KEYCERT_CRYPTO_P384, 96, false},
		{"P521", KEYCERT_CRYPTO_P521, 132, false},
		{"X25519", KEYCERT_CRYPTO_X25519, 32, false},
		{"MLKEM512", KEYCERT_CRYPTO_MLKEM512_X25519, 32, false},
		{"MLKEM768", KEYCERT_CRYPTO_MLKEM768_X25519, 32, false},
		{"MLKEM1024", KEYCERT_CRYPTO_MLKEM1024_X25519, 32, false},
		{"Invalid", 9999, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			size, err := GetCryptoKeySize(tt.cryptoType)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.wantSize, size)
			}
		})
	}
}

func TestGetSignatureSize(t *testing.T) {
	tests := []struct {
		name        string
		signingType int
		wantSize    int
		wantErr     bool
	}{
		{"DSA_SHA1", KEYCERT_SIGN_DSA_SHA1, 40, false},
		{"P256", KEYCERT_SIGN_P256, 64, false},
		{"P384", KEYCERT_SIGN_P384, 96, false},
		{"P521", KEYCERT_SIGN_P521, 132, false},
		{"RSA2048", KEYCERT_SIGN_RSA2048, 256, false},
		{"RSA3072", KEYCERT_SIGN_RSA3072, 384, false},
		{"RSA4096", KEYCERT_SIGN_RSA4096, 512, false},
		{"ED25519", KEYCERT_SIGN_ED25519, 64, false},
		{"ED25519PH", KEYCERT_SIGN_ED25519PH, 64, false},
		{"Invalid", 9999, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			size, err := GetSignatureSize(tt.signingType)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.wantSize, size)
			}
		})
	}
}

func TestSigningKeySizes(t *testing.T) {
	for _, sigType := range testAllSigningTypes {
		info, exists := SigningKeySizes[sigType]
		assert.True(t, exists, "Signing type %d should exist in map", sigType)
		assert.Greater(t, info.SignatureSize, 0, "Signature size should be positive")
		assert.Greater(t, info.SigningPublicKeySize, 0, "Public key size should be positive")
		assert.Greater(t, info.SigningPrivateKeySize, 0, "Private key size should be positive")
	}
}

func TestCryptoKeySizes(t *testing.T) {
	expectedTypes := []int{
		KEYCERT_CRYPTO_ELG,
		KEYCERT_CRYPTO_P256,
		KEYCERT_CRYPTO_P384,
		KEYCERT_CRYPTO_P521,
		KEYCERT_CRYPTO_X25519,
		KEYCERT_CRYPTO_MLKEM512_X25519,
		KEYCERT_CRYPTO_MLKEM768_X25519,
		KEYCERT_CRYPTO_MLKEM1024_X25519,
	}

	for _, cryptoType := range expectedTypes {
		info, exists := CryptoKeySizes[cryptoType]
		assert.True(t, exists, "Crypto type %d should exist in map", cryptoType)
		assert.Greater(t, info.CryptoPublicKeySize, 0, "Public key size should be positive")
		assert.Greater(t, info.CryptoPrivateKeySize, 0, "Private key size should be positive")
	}
}

// Benchmark tests
func BenchmarkGetKeySizes(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = GetKeySizes(KEYCERT_SIGN_ED25519, KEYCERT_CRYPTO_X25519)
	}
}

func BenchmarkGetSigningKeySize(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = GetSigningKeySize(KEYCERT_SIGN_ED25519)
	}
}

func BenchmarkGetCryptoKeySize(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = GetCryptoKeySize(KEYCERT_CRYPTO_X25519)
	}
}
