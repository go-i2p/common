package signature

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewSignatureFromBytesValidation(t *testing.T) {
	// Create with mismatched data size
	data := make([]byte, 10)
	_, err := NewSignatureFromBytes(data, SIGNATURE_TYPE_EDDSA_SHA512_ED25519)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not match expected")

	// Create with correct data size
	correctData := make([]byte, EdDSA_SHA512_Ed25519_SIZE)
	sig, err := NewSignatureFromBytes(correctData, SIGNATURE_TYPE_EDDSA_SHA512_ED25519)
	require.NoError(t, err)
	assert.Equal(t, SIGNATURE_TYPE_EDDSA_SHA512_ED25519, sig.Type())
	assert.Equal(t, EdDSA_SHA512_Ed25519_SIZE, sig.Len())

	err = sig.Validate()
	require.NoError(t, err)

	// Invalid signature type
	_, err = NewSignatureFromBytes(make([]byte, 64), 9999)
	require.Error(t, err)

	// Negative sigType
	_, err = NewSignatureFromBytes(make([]byte, 40), -1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "out of valid range")

	// sigType > 65535
	_, err = NewSignatureFromBytes(make([]byte, 40), 70000)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "out of valid range")
}

func TestSignatureValidate(t *testing.T) {
	t.Run("nil signature via ValidatePtr", func(t *testing.T) {
		var sig *Signature
		err := ValidatePtr(sig)
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
		assert.NoError(t, sig.Validate())
	})

	t.Run("valid DSA signature", func(t *testing.T) {
		data := make([]byte, DSA_SHA1_SIZE)
		for i := range data {
			data[i] = byte(i % 256)
		}
		sig, err := NewSignatureFromBytes(data, SIGNATURE_TYPE_DSA_SHA1)
		require.NoError(t, err)
		assert.NoError(t, sig.Validate())
	})

	t.Run("valid RSA-2048 signature", func(t *testing.T) {
		data := make([]byte, RSA_SHA256_2048_SIZE)
		for i := range data {
			data[i] = byte(i % 256)
		}
		sig, err := NewSignatureFromBytes(data, SIGNATURE_TYPE_RSA_SHA256_2048)
		require.NoError(t, err)
		assert.NoError(t, sig.Validate())
	})

	t.Run("invalid signature type", func(t *testing.T) {
		_, err := NewSignatureFromBytes(make([]byte, 64), 9999)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unknown signature type")
	})

	t.Run("incorrect data size for type", func(t *testing.T) {
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
		for _, tc := range supportedSigTypes() {
			data := make([]byte, tc.Size)
			sig, err := NewSignatureFromBytes(data, tc.SigType)
			require.NoError(t, err, "NewSignatureFromBytes should succeed for type %d", tc.SigType)
			assert.NoError(t, sig.Validate(), "signature type %d should be valid", tc.SigType)
		}
	})
}

func TestSignatureIsValid(t *testing.T) {
	t.Run("nil signature via ValidatePtr", func(t *testing.T) {
		var sig *Signature
		assert.Error(t, ValidatePtr(sig))
	})

	t.Run("valid signature", func(t *testing.T) {
		data := make([]byte, EdDSA_SHA512_Ed25519_SIZE)
		sig, err := NewSignatureFromBytes(data, SIGNATURE_TYPE_EDDSA_SHA512_ED25519)
		require.NoError(t, err)
		assert.True(t, sig.IsValid())
	})

	t.Run("invalid signature type", func(t *testing.T) {
		_, err := NewSignatureFromBytes(make([]byte, 64), 9999)
		assert.Error(t, err)
	})

	t.Run("incorrect data size", func(t *testing.T) {
		_, err := NewSignatureFromBytes(make([]byte, 40), SIGNATURE_TYPE_EDDSA_SHA512_ED25519)
		assert.Error(t, err)
	})
}

func TestValidatePtrFunction(t *testing.T) {
	t.Run("nil pointer", func(t *testing.T) {
		var sig *Signature
		err := ValidatePtr(sig)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "signature is nil")
	})

	t.Run("valid pointer", func(t *testing.T) {
		data := make([]byte, EdDSA_SHA512_Ed25519_SIZE)
		sig, err := NewSignatureFromBytes(data, SIGNATURE_TYPE_EDDSA_SHA512_ED25519)
		require.NoError(t, err)
		assert.NoError(t, ValidatePtr(&sig))
	})

	t.Run("zero value pointer", func(t *testing.T) {
		sig := &Signature{}
		err := ValidatePtr(sig)
		require.Error(t, err,
			"zero-value Signature should fail validation (type 0 = DSA_SHA1 but data is empty)")
	})
}
