package signature

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSignatureEqual(t *testing.T) {
	t.Run("equal signatures", func(t *testing.T) {
		data1 := make([]byte, EdDSA_SHA512_Ed25519_SIZE)
		data2 := make([]byte, EdDSA_SHA512_Ed25519_SIZE)
		for i := range data1 {
			data1[i] = byte(i % 256)
			data2[i] = byte(i % 256)
		}
		sig1, err := NewSignatureFromBytes(data1, SIGNATURE_TYPE_EDDSA_SHA512_ED25519)
		require.NoError(t, err)
		sig2, err := NewSignatureFromBytes(data2, SIGNATURE_TYPE_EDDSA_SHA512_ED25519)
		require.NoError(t, err)
		assert.True(t, sig1.Equal(&sig2))
	})

	t.Run("different data", func(t *testing.T) {
		data1 := make([]byte, EdDSA_SHA512_Ed25519_SIZE)
		data2 := make([]byte, EdDSA_SHA512_Ed25519_SIZE)
		for i := range data1 {
			data1[i] = byte(i % 256)
			data2[i] = byte((i + 1) % 256)
		}
		sig1, err := NewSignatureFromBytes(data1, SIGNATURE_TYPE_EDDSA_SHA512_ED25519)
		require.NoError(t, err)
		sig2, err := NewSignatureFromBytes(data2, SIGNATURE_TYPE_EDDSA_SHA512_ED25519)
		require.NoError(t, err)
		assert.False(t, sig1.Equal(&sig2))
	})

	t.Run("different types", func(t *testing.T) {
		data1 := make([]byte, EdDSA_SHA512_Ed25519_SIZE)
		data2 := make([]byte, ECDSA_SHA256_P256_SIZE)
		sig1, err := NewSignatureFromBytes(data1, SIGNATURE_TYPE_EDDSA_SHA512_ED25519)
		require.NoError(t, err)
		sig2, err := NewSignatureFromBytes(data2, SIGNATURE_TYPE_ECDSA_SHA256_P256)
		require.NoError(t, err)
		assert.False(t, sig1.Equal(&sig2))
	})

	t.Run("different types different sizes", func(t *testing.T) {
		data1 := make([]byte, DSA_SHA1_SIZE)
		data2 := make([]byte, EdDSA_SHA512_Ed25519_SIZE)
		sig1, err := NewSignatureFromBytes(data1, SIGNATURE_TYPE_DSA_SHA1)
		require.NoError(t, err)
		sig2, err := NewSignatureFromBytes(data2, SIGNATURE_TYPE_EDDSA_SHA512_ED25519)
		require.NoError(t, err)
		assert.False(t, sig1.Equal(&sig2))
	})

	t.Run("nil other", func(t *testing.T) {
		data := make([]byte, EdDSA_SHA512_Ed25519_SIZE)
		sig, err := NewSignatureFromBytes(data, SIGNATURE_TYPE_EDDSA_SHA512_ED25519)
		require.NoError(t, err)
		assert.False(t, sig.Equal(nil))
	})

	t.Run("both empty data rejected", func(t *testing.T) {
		_, err := NewSignatureFromBytes([]byte{}, SIGNATURE_TYPE_EDDSA_SHA512_ED25519)
		assert.Error(t, err, "empty data should be rejected for typed signatures")
	})
}

func TestSignatureRoundTrip(t *testing.T) {
	for _, tc := range supportedSigTypes() {
		t.Run(tc.Name, func(t *testing.T) {
			// Create original data with non-trivial pattern
			original := make([]byte, tc.Size+10)
			for i := range original {
				original[i] = byte((i * 37) ^ 0xAB)
			}

			// Create signature via ReadSignature
			sig1, remainder, err := ReadSignature(original, tc.SigType)
			require.NoError(t, err)
			assert.Len(t, remainder, 10)

			// Extract bytes and reconstruct
			bytes := sig1.Bytes()
			sig2, err := NewSignatureFromBytes(bytes, tc.SigType)
			require.NoError(t, err)

			// Verify equality
			assert.True(t, sig1.Equal(&sig2),
				"round-trip should produce equal signatures")
			assert.Equal(t, sig1.Type(), sig2.Type())
			assert.Equal(t, sig1.Len(), sig2.Len())
			assert.Equal(t, sig1.Bytes(), sig2.Bytes())

			// Reconstruct again via ReadSignature on extracted bytes
			padded := append(bytes, 0xDE, 0xAD)
			sig3, rem3, err := ReadSignature(padded, tc.SigType)
			require.NoError(t, err)
			assert.Equal(t, []byte{0xDE, 0xAD}, rem3)
			assert.True(t, sig1.Equal(&sig3))
		})
	}
}

func TestSignatureBufferIsolation(t *testing.T) {
	buf := make([]byte, EdDSA_SHA512_Ed25519_SIZE)
	for i := range buf {
		buf[i] = byte(i)
	}

	sig, _, err := ReadSignature(buf, SIGNATURE_TYPE_EDDSA_SHA512_ED25519)
	require.NoError(t, err)

	originalBytes := make([]byte, len(sig.Bytes()))
	copy(originalBytes, sig.Bytes())

	// Mutate the original buffer
	for i := range buf {
		buf[i] = 0xFF
	}

	assert.Equal(t, originalBytes, sig.Bytes(),
		"signature data should be isolated from caller's buffer")
}

func TestSignatureStringFormat(t *testing.T) {
	testCases := []struct {
		sigType  int
		dataLen  int
		expected string
	}{
		{SIGNATURE_TYPE_EDDSA_SHA512_ED25519, 64, "Signature{type: 7, length: 64}"},
		{SIGNATURE_TYPE_DSA_SHA1, 40, "Signature{type: 0, length: 40}"},
		{SIGNATURE_TYPE_RSA_SHA256_2048, 256, "Signature{type: 4, length: 256}"},
		{SIGNATURE_TYPE_REDDSA_SHA512_ED25519, 64, "Signature{type: 11, length: 64}"},
		{SIGNATURE_TYPE_ECDSA_SHA512_P521, 132, "Signature{type: 3, length: 132}"},
	}

	for _, tc := range testCases {
		t.Run(tc.expected, func(t *testing.T) {
			data := make([]byte, tc.dataLen)
			sig, err := NewSignatureFromBytes(data, tc.sigType)
			require.NoError(t, err)
			assert.Equal(t, tc.expected, sig.String())
		})
	}

	t.Run("empty data rejected", func(t *testing.T) {
		_, err := NewSignatureFromBytes([]byte{}, 7)
		assert.Error(t, err)
	})
}

func TestBytesMutationIsolation(t *testing.T) {
	original := make([]byte, EdDSA_SHA512_Ed25519_SIZE)
	for i := range original {
		original[i] = byte(i)
	}

	sig, err := NewSignatureFromBytes(original, SIGNATURE_TYPE_EDDSA_SHA512_ED25519)
	require.NoError(t, err)

	bytes1 := sig.Bytes()
	expected := make([]byte, len(bytes1))
	copy(expected, bytes1)

	// Mutate the returned bytes
	for i := range bytes1 {
		bytes1[i] = 0xFF
	}

	bytes2 := sig.Bytes()
	assert.Equal(t, expected, bytes2,
		"Bytes() must return a copy; mutating the return value should not affect internal data")

	bytes3 := sig.Bytes()
	bytes3[0] = 0xAA
	bytes4 := sig.Bytes()
	assert.Equal(t, expected, bytes4,
		"each Bytes() call should return an independent copy")
}

func TestNewSignatureReturnsNonNil(t *testing.T) {
	data := make([]byte, EdDSA_SHA512_Ed25519_SIZE+10)
	for i := range data {
		data[i] = byte(i % 256)
	}

	sig, remainder, err := NewSignature(data, SIGNATURE_TYPE_EDDSA_SHA512_ED25519)
	require.NoError(t, err)
	require.NotNil(t, sig, "NewSignature must return a non-nil pointer on success")
	assert.Equal(t, SIGNATURE_TYPE_EDDSA_SHA512_ED25519, sig.Type())
	assert.Equal(t, EdDSA_SHA512_Ed25519_SIZE, sig.Len())
	assert.Len(t, remainder, 10)
}

func TestSerializeMethod(t *testing.T) {
	data := make([]byte, EdDSA_SHA512_Ed25519_SIZE)
	for i := range data {
		data[i] = byte((i * 7) ^ 0x3C)
	}

	sig, err := NewSignatureFromBytes(data, SIGNATURE_TYPE_EDDSA_SHA512_ED25519)
	require.NoError(t, err)

	serialized := sig.Serialize()
	assert.Equal(t, data, serialized,
		"Serialize() should return the raw signature bytes")

	serialized[0] ^= 0xFF
	assert.NotEqual(t, serialized, sig.Bytes(),
		"mutating Serialize() output should not affect internal data")

	assert.Equal(t, sig.Bytes(), sig.Serialize(),
		"Serialize() and Bytes() should return equal data")
}

func TestValueReceiverConsistency(t *testing.T) {
	data := make([]byte, EdDSA_SHA512_Ed25519_SIZE)
	for i := range data {
		data[i] = byte(i)
	}
	sig, err := NewSignatureFromBytes(data, SIGNATURE_TYPE_EDDSA_SHA512_ED25519)
	require.NoError(t, err)

	assert.Equal(t, SIGNATURE_TYPE_EDDSA_SHA512_ED25519, sig.Type())
	assert.Equal(t, EdDSA_SHA512_Ed25519_SIZE, sig.Len())
	assert.NotNil(t, sig.Bytes())
	assert.NoError(t, sig.Validate())
	assert.True(t, sig.IsValid())
	assert.NotEmpty(t, sig.String())
	assert.NotNil(t, sig.Serialize())
}
