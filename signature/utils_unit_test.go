package signature

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReadSignature(t *testing.T) {
	assert := assert.New(t)

	sigTypes := []int{
		SIGNATURE_TYPE_DSA_SHA1, SIGNATURE_TYPE_ECDSA_SHA256_P256,
		SIGNATURE_TYPE_ECDSA_SHA384_P384, SIGNATURE_TYPE_ECDSA_SHA512_P521,
		SIGNATURE_TYPE_RSA_SHA256_2048, SIGNATURE_TYPE_RSA_SHA384_3072,
		SIGNATURE_TYPE_RSA_SHA512_4096, SIGNATURE_TYPE_EDDSA_SHA512_ED25519,
		SIGNATURE_TYPE_EDDSA_SHA512_ED25519PH, SIGNATURE_TYPE_REDDSA_SHA512_ED25519,
	}
	sigLengths := []int{
		DSA_SHA1_SIZE, ECDSA_SHA256_P256_SIZE,
		ECDSA_SHA384_P384_SIZE, ECDSA_SHA512_P521_SIZE,
		RSA_SHA256_2048_SIZE, RSA_SHA384_3072_SIZE,
		RSA_SHA512_4096_SIZE, EdDSA_SHA512_Ed25519_SIZE,
		EdDSA_SHA512_Ed25519ph_SIZE, RedDSA_SHA512_Ed25519_SIZE,
	}

	dataLen := 1024
	data := []byte{}
	for i := 0; i < dataLen; i++ {
		data = append(data, byte(i%10))
	}

	for i, sigType := range sigTypes {
		sig, rem, err := ReadSignature(data, sigType)
		assert.Nil(err, "no errors should be returned")
		assert.Equal(sig.Bytes(), data[:sigLengths[i]], "signature bytes should be sliced from data")
		assert.Equal(sig.Type(), sigType, "signature type should match input")
		assert.Equal(rem, data[sigLengths[i]:], "remainder should be sliced from data")
	}
}

func TestNewSignature(t *testing.T) {
	assert := assert.New(t)

	data := []byte{}
	sigLength := EdDSA_SHA512_Ed25519_SIZE
	remLength := 20
	for i := 0; i < sigLength+remLength; i++ {
		data = append(data, byte(i%10))
	}
	sigType := SIGNATURE_TYPE_EDDSA_SHA512_ED25519

	sig, rem, err := NewSignature(data, sigType)
	assert.Nil(err, "no errors should be returned")
	assert.Equal(sig.Bytes(), data[:sigLength], "signature bytes should be sliced from data")
	assert.Equal(sig.Type(), sigType, "signature type should match input")
	assert.Equal(rem, data[sigLength:], "remainder should be sliced from data")
}

func TestSignatureSizeExported(t *testing.T) {
	for _, tc := range supportedSigTypes() {
		size, err := SignatureSize(tc.SigType)
		assert.NoError(t, err)
		assert.Equal(t, tc.Size, size, "SignatureSize(%d)", tc.SigType)
	}

	// Unknown type returns error
	_, err := SignatureSize(9999)
	assert.Error(t, err)

	// Negative type returns error
	_, err = SignatureSize(-1)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "out of valid range")

	// > 65535 returns error
	_, err = SignatureSize(70000)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "out of valid range")
}

func TestSignatureSizeIsExported(t *testing.T) {
	tests := []struct {
		sigType int
		size    int
	}{
		{SIGNATURE_TYPE_DSA_SHA1, 40},
		{SIGNATURE_TYPE_ECDSA_SHA256_P256, 64},
		{SIGNATURE_TYPE_ECDSA_SHA384_P384, 96},
		{SIGNATURE_TYPE_ECDSA_SHA512_P521, 132},
		{SIGNATURE_TYPE_RSA_SHA256_2048, 256},
		{SIGNATURE_TYPE_RSA_SHA384_3072, 384},
		{SIGNATURE_TYPE_RSA_SHA512_4096, 512},
		{SIGNATURE_TYPE_EDDSA_SHA512_ED25519, 64},
		{SIGNATURE_TYPE_EDDSA_SHA512_ED25519PH, 64},
		{SIGNATURE_TYPE_REDDSA_SHA512_ED25519, 64},
	}

	for _, tt := range tests {
		size, err := SignatureSize(tt.sigType)
		require.NoError(t, err, "SignatureSize(%d)", tt.sigType)
		assert.Equal(t, tt.size, size, "SignatureSize(%d)", tt.sigType)
	}
}
