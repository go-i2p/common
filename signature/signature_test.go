package signature

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReadSignatureErrors(t *testing.T) {
	assert := assert.New(t)

	data := []byte{0xbe, 0xef}
	unsupportedSigType := 1000
	_, _, err := ReadSignature(data, unsupportedSigType)
	assert.NotNil(err, "unsupported signature error should be reported")

	sigType := SIGNATURE_TYPE_DSA_SHA1
	_, _, err = ReadSignature(data, sigType)
	assert.NotNil(err, "insufficient data error should be reported")
}

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
		assert.Equal(rem, data[sigLengths[i]:], "remainder should be sliced from data ")
	}
}

func TestNewSignatureError(t *testing.T) {
	assert := assert.New(t)

	data := []byte{0xbe, 0xef}
	unsupportedSigType := 1000
	_, _, err := NewSignature(data, unsupportedSigType)
	assert.NotNil(err, "NewSignature error should be reported")
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
	assert.Equal(rem, data[sigLength:], "remainder should be sliced from data ")
}

func TestSignatureValidate(t *testing.T) {
	t.Run("nil signature", func(t *testing.T) {
		var sig *Signature
		err := sig.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "signature is nil")
	})

	t.Run("valid EdDSA signature", func(t *testing.T) {
		data := make([]byte, EdDSA_SHA512_Ed25519_SIZE)
		for i := range data {
			data[i] = byte(i % 256)
		}
		sig, err := NewSignatureFromBytes(data, SIGNATURE_TYPE_EDDSA_SHA512_ED25519)
		require.NoError(t, err)
		err = sig.Validate()
		require.NoError(t, err)
	})

	t.Run("valid DSA signature", func(t *testing.T) {
		data := make([]byte, DSA_SHA1_SIZE)
		for i := range data {
			data[i] = byte(i % 256)
		}
		sig, err := NewSignatureFromBytes(data, SIGNATURE_TYPE_DSA_SHA1)
		require.NoError(t, err)
		err = sig.Validate()
		require.NoError(t, err)
	})

	t.Run("valid RSA-2048 signature", func(t *testing.T) {
		data := make([]byte, RSA_SHA256_2048_SIZE)
		for i := range data {
			data[i] = byte(i % 256)
		}
		sig, err := NewSignatureFromBytes(data, SIGNATURE_TYPE_RSA_SHA256_2048)
		require.NoError(t, err)
		err = sig.Validate()
		require.NoError(t, err)
	})

	t.Run("invalid signature type", func(t *testing.T) {
		data := make([]byte, 64)
		_, err := NewSignatureFromBytes(data, 9999)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unknown signature type")
	})

	t.Run("incorrect data size for type", func(t *testing.T) {
		// EdDSA should be 64 bytes, but provide 40
		data := make([]byte, DSA_SHA1_SIZE)
		_, err := NewSignatureFromBytes(data, SIGNATURE_TYPE_EDDSA_SHA512_ED25519)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "does not match expected")
	})

	t.Run("empty data", func(t *testing.T) {
		_, err := NewSignatureFromBytes([]byte{}, SIGNATURE_TYPE_EDDSA_SHA512_ED25519)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "does not match expected")
	})

	t.Run("all supported signature types", func(t *testing.T) {
		testCases := []struct {
			sigType int
			size    int
		}{
			{SIGNATURE_TYPE_DSA_SHA1, DSA_SHA1_SIZE},
			{SIGNATURE_TYPE_ECDSA_SHA256_P256, ECDSA_SHA256_P256_SIZE},
			{SIGNATURE_TYPE_ECDSA_SHA384_P384, ECDSA_SHA384_P384_SIZE},
			{SIGNATURE_TYPE_ECDSA_SHA512_P521, ECDSA_SHA512_P521_SIZE},
			{SIGNATURE_TYPE_RSA_SHA256_2048, RSA_SHA256_2048_SIZE},
			{SIGNATURE_TYPE_RSA_SHA384_3072, RSA_SHA384_3072_SIZE},
			{SIGNATURE_TYPE_RSA_SHA512_4096, RSA_SHA512_4096_SIZE},
			{SIGNATURE_TYPE_EDDSA_SHA512_ED25519, EdDSA_SHA512_Ed25519_SIZE},
			{SIGNATURE_TYPE_EDDSA_SHA512_ED25519PH, EdDSA_SHA512_Ed25519ph_SIZE},
			{SIGNATURE_TYPE_REDDSA_SHA512_ED25519, RedDSA_SHA512_Ed25519_SIZE},
		}

		for _, tc := range testCases {
			data := make([]byte, tc.size)
			sig, err := NewSignatureFromBytes(data, tc.sigType)
			require.NoError(t, err, "NewSignatureFromBytes should succeed for type %d", tc.sigType)
			err = sig.Validate()
			require.NoError(t, err, "signature type %d should be valid", tc.sigType)
		}
	})
}

func TestSignatureIsValid(t *testing.T) {
	t.Run("nil signature", func(t *testing.T) {
		var sig *Signature
		assert.False(t, sig.IsValid())
	})

	t.Run("valid signature", func(t *testing.T) {
		data := make([]byte, EdDSA_SHA512_Ed25519_SIZE)
		sig, err := NewSignatureFromBytes(data, SIGNATURE_TYPE_EDDSA_SHA512_ED25519)
		require.NoError(t, err)
		assert.True(t, sig.IsValid())
	})

	t.Run("invalid signature type", func(t *testing.T) {
		data := make([]byte, 64)
		_, err := NewSignatureFromBytes(data, 9999)
		assert.Error(t, err)
	})

	t.Run("incorrect data size", func(t *testing.T) {
		data := make([]byte, 40)
		_, err := NewSignatureFromBytes(data, SIGNATURE_TYPE_EDDSA_SHA512_ED25519)
		assert.Error(t, err)
	})
}
