package key_certificate

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidateSigningType(t *testing.T) {
	tests := []struct {
		name        string
		signingType int
		wantErr     bool
	}{
		{"DSA_SHA1", KEYCERT_SIGN_DSA_SHA1, false},
		{"P256", KEYCERT_SIGN_P256, false},
		{"P384", KEYCERT_SIGN_P384, false},
		{"P521", KEYCERT_SIGN_P521, false},
		{"RSA2048", KEYCERT_SIGN_RSA2048, false},
		{"RSA3072", KEYCERT_SIGN_RSA3072, false},
		{"RSA4096", KEYCERT_SIGN_RSA4096, false},
		{"ED25519", KEYCERT_SIGN_ED25519, false},
		{"ED25519PH", KEYCERT_SIGN_ED25519PH, false},
		{"RedDSA", KEYCERT_SIGN_REDDSA_ED25519, false},
		{"Experimental_Start", KEYCERT_SIGN_EXPERIMENTAL_START, false},
		{"Experimental_End", KEYCERT_SIGN_EXPERIMENTAL_END, false},
		{"Invalid_Low", -1, true},
		{"Invalid_High", 100, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateSigningType(tt.signingType)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateCryptoType(t *testing.T) {
	tests := []struct {
		name       string
		cryptoType int
		wantErr    bool
	}{
		{"ElGamal", KEYCERT_CRYPTO_ELG, false},
		{"P256", KEYCERT_CRYPTO_P256, false},
		{"P384", KEYCERT_CRYPTO_P384, false},
		{"P521", KEYCERT_CRYPTO_P521, false},
		{"X25519", KEYCERT_CRYPTO_X25519, false},
		{"MLKEM512", KEYCERT_CRYPTO_MLKEM512_X25519, false},
		{"MLKEM768", KEYCERT_CRYPTO_MLKEM768_X25519, false},
		{"MLKEM1024", KEYCERT_CRYPTO_MLKEM1024_X25519, false},
		{"Experimental_Start", KEYCERT_CRYPTO_EXPERIMENTAL_START, false},
		{"Experimental_End", KEYCERT_CRYPTO_EXPERIMENTAL_END, false},
		{"Invalid_Low", -1, true},
		{"Invalid_High", 100, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateCryptoType(tt.cryptoType)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestConstructSigningPublicKeyByType_InsufficientData verifies bounds checking.
func TestConstructSigningPublicKeyByType_InsufficientData(t *testing.T) {
	tests := []struct {
		name    string
		sigType int
		dataLen int
	}{
		{"P256_TooShort", KEYCERT_SIGN_P256, 32},
		{"P384_TooShort", KEYCERT_SIGN_P384, 48},
		{"DSA_TooShort", KEYCERT_SIGN_DSA_SHA1, 64},
		{"Ed25519_TooShort", KEYCERT_SIGN_ED25519, 16},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := make([]byte, tt.dataLen)
			spk, err := ConstructSigningPublicKeyByType(data, tt.sigType)
			assert.Error(t, err, "Should return error for insufficient data")
			assert.Nil(t, spk)
		})
	}
}
