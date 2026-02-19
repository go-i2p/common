package offline_signature

import (
	"testing"

	"github.com/go-i2p/common/key_certificate"
	"github.com/go-i2p/common/signature"
	"github.com/stretchr/testify/assert"
)

func TestOfflineSignatureMinimumSize(t *testing.T) {
	// Ed25519 gives us the minimum: 4 + 2 + 32 + 64 = 102
	assert.Equal(t, 102, OFFLINE_SIGNATURE_MIN_SIZE, "minimum size constant should be 102")

	// Verify actual minimum
	transientKey := make([]byte, key_certificate.KEYCERT_SIGN_ED25519_SIZE)
	sig := make([]byte, signature.EdDSA_SHA512_Ed25519_SIZE)

	offlineSig, err := NewOfflineSignature(
		uint32(1735689600),
		key_certificate.KEYCERT_SIGN_ED25519,
		transientKey,
		sig,
		signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519,
	)
	assert.NoError(t, err)

	assert.GreaterOrEqual(t, offlineSig.Len(), OFFLINE_SIGNATURE_MIN_SIZE,
		"actual OfflineSignature should be at least minimum size")
}

func TestOfflineSignatureEddsaSize(t *testing.T) {
	t.Run("eddsa_size_value", func(t *testing.T) {
		expected := EXPIRES_SIZE + SIGTYPE_SIZE + key_certificate.KEYCERT_SIGN_ED25519_SIZE + signature.EdDSA_SHA512_Ed25519_SIZE
		assert.Equal(t, expected, OFFLINE_SIGNATURE_EDDSA_SIZE,
			"EDDSA_SIZE should be 4+2+32+64 = 102")
	})

	t.Run("deprecated_alias", func(t *testing.T) {
		assert.Equal(t, OFFLINE_SIGNATURE_EDDSA_SIZE, OFFLINE_SIGNATURE_MIN_SIZE,
			"OFFLINE_SIGNATURE_MIN_SIZE should equal OFFLINE_SIGNATURE_EDDSA_SIZE (deprecated alias)")
	})

	t.Run("mixed_type_smaller_than_eddsa", func(t *testing.T) {
		// Ed25519 transient (32 bytes) + DSA_SHA1 signature (40 bytes) = 78 bytes
		mixedSize := EXPIRES_SIZE + SIGTYPE_SIZE + key_certificate.KEYCERT_SIGN_ED25519_SIZE + signature.DSA_SHA1_SIZE
		assert.Less(t, mixedSize, OFFLINE_SIGNATURE_EDDSA_SIZE,
			"mixed-type combination (Ed25519+DSA_SHA1) is smaller than EDDSA_SIZE, "+
				"proving the constant is not the true minimum across all type combinations")
	})
}

func TestExpiresSizeConstant(t *testing.T) {
	assert.Equal(t, 4, EXPIRES_SIZE)
}

func TestSigtypeSizeConstant(t *testing.T) {
	assert.Equal(t, 2, SIGTYPE_SIZE)
}
