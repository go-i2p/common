package signature

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDSA_SHA1_SizeConstant(t *testing.T) {
	assert.Equal(t, 40, DSA_SHA1_SIZE)
}

func TestECDSA_SHA256_P256_SizeConstant(t *testing.T) {
	assert.Equal(t, 64, ECDSA_SHA256_P256_SIZE)
}

func TestECDSA_SHA384_P384_SizeConstant(t *testing.T) {
	assert.Equal(t, 96, ECDSA_SHA384_P384_SIZE)
}

func TestECDSA_SHA512_P521_SizeConstant(t *testing.T) {
	assert.Equal(t, 132, ECDSA_SHA512_P521_SIZE)
}

func TestRSA_SHA256_2048_SizeConstant(t *testing.T) {
	assert.Equal(t, 256, RSA_SHA256_2048_SIZE)
}

func TestRSA_SHA384_3072_SizeConstant(t *testing.T) {
	assert.Equal(t, 384, RSA_SHA384_3072_SIZE)
}

func TestRSA_SHA512_4096_SizeConstant(t *testing.T) {
	assert.Equal(t, 512, RSA_SHA512_4096_SIZE)
}

func TestEdDSA_SHA512_Ed25519_SizeConstant(t *testing.T) {
	assert.Equal(t, 64, EdDSA_SHA512_Ed25519_SIZE)
}

func TestEdDSA_SHA512_Ed25519ph_SizeConstant(t *testing.T) {
	assert.Equal(t, 64, EdDSA_SHA512_Ed25519ph_SIZE)
}

func TestRedDSA_SHA512_Ed25519_SizeConstant(t *testing.T) {
	assert.Equal(t, 64, RedDSA_SHA512_Ed25519_SIZE)
}

func TestDeprecatedP512Alias(t *testing.T) {
	assert.Equal(t, ECDSA_SHA512_P521_SIZE, ECDSA_SHA512_P512_SIZE,
		"deprecated alias should equal the correctly-named constant")
	assert.Equal(t, 132, ECDSA_SHA512_P521_SIZE,
		"ECDSA_SHA512_P521_SIZE should be 132 bytes per spec")
}

func TestSignatureTypeConstants(t *testing.T) {
	assert.Equal(t, 0, SIGNATURE_TYPE_DSA_SHA1)
	assert.Equal(t, 1, SIGNATURE_TYPE_ECDSA_SHA256_P256)
	assert.Equal(t, 2, SIGNATURE_TYPE_ECDSA_SHA384_P384)
	assert.Equal(t, 3, SIGNATURE_TYPE_ECDSA_SHA512_P521)
	assert.Equal(t, 4, SIGNATURE_TYPE_RSA_SHA256_2048)
	assert.Equal(t, 5, SIGNATURE_TYPE_RSA_SHA384_3072)
	assert.Equal(t, 6, SIGNATURE_TYPE_RSA_SHA512_4096)
	assert.Equal(t, 7, SIGNATURE_TYPE_EDDSA_SHA512_ED25519)
	assert.Equal(t, 8, SIGNATURE_TYPE_EDDSA_SHA512_ED25519PH)
	assert.Equal(t, 9, SIGNATURE_TYPE_GOST_R3410_2012_512)
	assert.Equal(t, 10, SIGNATURE_TYPE_GOST_R3410_2012_1024)
	assert.Equal(t, 11, SIGNATURE_TYPE_REDDSA_SHA512_ED25519)
	assert.Equal(t, 12, SIGNATURE_TYPE_MLDSA_RESERVED_START)
	assert.Equal(t, 20, SIGNATURE_TYPE_MLDSA_RESERVED_END)
	assert.Equal(t, 65280, SIGNATURE_TYPE_EXPERIMENTAL_START)
	assert.Equal(t, 65534, SIGNATURE_TYPE_EXPERIMENTAL_END)
	assert.Equal(t, 65535, SIGNATURE_TYPE_FUTURE_EXPANSION)
}
