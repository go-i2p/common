package offline_signature

import (
	"encoding/binary"
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

func TestOfflineSignatureHeaderSize(t *testing.T) {
	t.Run("header_size_value", func(t *testing.T) {
		assert.Equal(t, 6, OFFLINE_SIGNATURE_HEADER_SIZE,
			"OFFLINE_SIGNATURE_HEADER_SIZE should be EXPIRES_SIZE(4) + SIGTYPE_SIZE(2) = 6")
	})

	t.Run("header_size_is_true_minimum_parseable", func(t *testing.T) {
		// Anything less than OFFLINE_SIGNATURE_HEADER_SIZE cannot even parse the header
		data := make([]byte, OFFLINE_SIGNATURE_HEADER_SIZE-1)
		_, _, err := ReadOfflineSignature(data, signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519)
		assert.Error(t, err, "data shorter than header size should fail to parse")
	})

	t.Run("smallest_valid_offline_signature", func(t *testing.T) {
		// Ed25519 transient (32 bytes) + DSA_SHA1 destination signature (40 bytes) = 78 bytes total
		smallestSize := OFFLINE_SIGNATURE_HEADER_SIZE + key_certificate.KEYCERT_SIGN_ED25519_SIZE + signature.DSA_SHA1_SIZE
		assert.Equal(t, 78, smallestSize,
			"smallest valid OfflineSignature = 6 + 32 + 40 = 78 bytes")
		assert.Less(t, smallestSize, OFFLINE_SIGNATURE_MIN_SIZE,
			"smallest valid OfflineSignature is less than the deprecated OFFLINE_SIGNATURE_MIN_SIZE constant")
	})
}

func TestGOSTTypesReturnZeroSize(t *testing.T) {
	// GOST types 9 and 10 are reserved in the I2P spec but not implemented.
	// SigningPublicKeySize and SignatureSize correctly return 0 for unknown types,
	// which causes ReadOfflineSignature to reject them via ErrUnknownSignatureType.
	t.Run("gost_signing_key_size", func(t *testing.T) {
		assert.Equal(t, 0, SigningPublicKeySize(9), "GOST type 9 should return 0 key size")
		assert.Equal(t, 0, SigningPublicKeySize(10), "GOST type 10 should return 0 key size")
	})

	t.Run("gost_signature_size", func(t *testing.T) {
		assert.Equal(t, 0, SignatureSize(9), "GOST type 9 should return 0 signature size")
		assert.Equal(t, 0, SignatureSize(10), "GOST type 10 should return 0 signature size")
	})

	t.Run("gost_transient_type_rejected", func(t *testing.T) {
		data := make([]byte, 200)
		binary.BigEndian.PutUint32(data[0:4], 1735689600)
		binary.BigEndian.PutUint16(data[4:6], 9) // GOST type 9
		_, _, err := ReadOfflineSignature(data, signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519)
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrUnknownSignatureType)
	})
}
