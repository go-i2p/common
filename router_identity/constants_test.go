package router_identity

import (
	"testing"

	"github.com/go-i2p/common/key_certificate"
	"github.com/stretchr/testify/assert"
)

// TestDisallowedSigningKeyTypesEntries verifies the disallowed signing key types map
func TestDisallowedSigningKeyTypesEntries(t *testing.T) {
	expectedTypes := []int{
		key_certificate.KEYCERT_SIGN_RSA2048,
		key_certificate.KEYCERT_SIGN_RSA3072,
		key_certificate.KEYCERT_SIGN_RSA4096,
		key_certificate.KEYCERT_SIGN_ED25519PH,
		key_certificate.KEYCERT_SIGN_REDDSA_ED25519,
	}
	for _, sigType := range expectedTypes {
		_, ok := disallowedSigningKeyTypes[sigType]
		assert.True(t, ok, "signing key type %d should be in disallowedSigningKeyTypes", sigType)
	}
	assert.Len(t, disallowedSigningKeyTypes, len(expectedTypes),
		"disallowedSigningKeyTypes should contain exactly the expected entries")
}

// TestDisallowedCryptoKeyTypesEntries verifies the disallowed crypto key types map
func TestDisallowedCryptoKeyTypesEntries(t *testing.T) {
	expectedTypes := []int{
		key_certificate.KEYCERT_CRYPTO_MLKEM512_X25519,
		key_certificate.KEYCERT_CRYPTO_MLKEM768_X25519,
		key_certificate.KEYCERT_CRYPTO_MLKEM1024_X25519,
	}
	for _, cryptoType := range expectedTypes {
		_, ok := disallowedCryptoKeyTypes[cryptoType]
		assert.True(t, ok, "crypto key type %d should be in disallowedCryptoKeyTypes", cryptoType)
	}
	assert.Len(t, disallowedCryptoKeyTypes, len(expectedTypes),
		"disallowedCryptoKeyTypes should contain exactly the expected entries")
}

// TestDeprecatedConstants verifies the deprecated constant aliases
func TestDeprecatedConstants(t *testing.T) {
	assert.Equal(t, key_certificate.KEYCERT_CRYPTO_ELG, DEPRECATED_CRYPTO_ELGAMAL,
		"DEPRECATED_CRYPTO_ELGAMAL should equal KEYCERT_CRYPTO_ELG")
	assert.Equal(t, key_certificate.KEYCERT_SIGN_DSA_SHA1, DEPRECATED_SIGNING_DSA_SHA1,
		"DEPRECATED_SIGNING_DSA_SHA1 should equal KEYCERT_SIGN_DSA_SHA1")
}
