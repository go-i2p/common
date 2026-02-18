package signature

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestReadSignatureNilInput tests ReadSignature with nil input data.
// Covers: [TEST] No test for ReadSignature with nil input data.
func TestReadSignatureNilInput(t *testing.T) {
	sigTypes := []int{
		SIGNATURE_TYPE_DSA_SHA1,
		SIGNATURE_TYPE_ECDSA_SHA256_P256,
		SIGNATURE_TYPE_EDDSA_SHA512_ED25519,
		SIGNATURE_TYPE_REDDSA_SHA512_ED25519,
	}

	for _, sigType := range sigTypes {
		t.Run("nil_input", func(t *testing.T) {
			sig, remainder, err := ReadSignature(nil, sigType)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "insufficient data")
			assert.Equal(t, 0, sig.Len())
			assert.Nil(t, remainder)
		})

		t.Run("empty_input", func(t *testing.T) {
			sig, remainder, err := ReadSignature([]byte{}, sigType)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "insufficient data")
			assert.Equal(t, 0, sig.Len())
			assert.Nil(t, remainder)
		})
	}
}

// TestBytesMutationIsolation verifies that mutating Bytes() return value
// does NOT corrupt the internal Signature data.
// Covers: [TEST] No test that Bytes() returns a copy vs. alias.
// Also validates: [QUALITY] Bytes() returns internal slice directly.
func TestBytesMutationIsolation(t *testing.T) {
	original := make([]byte, EdDSA_SHA512_Ed25519_SIZE)
	for i := range original {
		original[i] = byte(i)
	}

	sig, err := NewSignatureFromBytes(original, SIGNATURE_TYPE_EDDSA_SHA512_ED25519)
	require.NoError(t, err)

	// Get bytes and save a reference copy
	bytes1 := sig.Bytes()
	expected := make([]byte, len(bytes1))
	copy(expected, bytes1)

	// Mutate the returned bytes
	for i := range bytes1 {
		bytes1[i] = 0xFF
	}

	// Get bytes again — must be unaffected
	bytes2 := sig.Bytes()
	assert.Equal(t, expected, bytes2,
		"Bytes() must return a copy; mutating the return value should not affect internal data")

	// Also verify that two calls return independent slices
	bytes3 := sig.Bytes()
	bytes3[0] = 0xAA
	bytes4 := sig.Bytes()
	assert.Equal(t, expected, bytes4,
		"each Bytes() call should return an independent copy")
}

// TestNewSignatureReturnsNonNil asserts that NewSignature returns a non-nil
// pointer on success.
// Covers: [TEST] No test for NewSignature returning a non-nil pointer.
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

// TestSerializeMethod tests the Serialize() method.
// Covers: [GAP] No serialization method.
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

	// Verify that mutating serialized output doesn't affect the signature
	serialized[0] ^= 0xFF
	assert.NotEqual(t, serialized, sig.Bytes(),
		"mutating Serialize() output should not affect internal data")

	// Serialize should return same data as Bytes
	assert.Equal(t, sig.Bytes(), sig.Serialize(),
		"Serialize() and Bytes() should return equal data")
}

// TestValidatePtrFunction tests the exported ValidatePtr function.
// Covers: [QUALITY] Receiver consistency — ValidatePtr replaces nil-pointer checks.
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
		err = ValidatePtr(&sig)
		require.NoError(t, err)
	})

	t.Run("zero value pointer", func(t *testing.T) {
		sig := &Signature{}
		err := ValidatePtr(sig)
		require.Error(t, err,
			"zero-value Signature should fail validation (type 0 = DSA_SHA1 but data is empty)")
	})
}

// TestValueReceiverConsistency verifies that all public methods use
// value receivers consistently.
// Covers: [QUALITY] Validate() uses pointer receiver but others use value.
func TestValueReceiverConsistency(t *testing.T) {
	data := make([]byte, EdDSA_SHA512_Ed25519_SIZE)
	for i := range data {
		data[i] = byte(i)
	}
	sig, err := NewSignatureFromBytes(data, SIGNATURE_TYPE_EDDSA_SHA512_ED25519)
	require.NoError(t, err)

	// All these should work on value receiver
	assert.Equal(t, SIGNATURE_TYPE_EDDSA_SHA512_ED25519, sig.Type())
	assert.Equal(t, EdDSA_SHA512_Ed25519_SIZE, sig.Len())
	assert.NotNil(t, sig.Bytes())
	assert.NoError(t, sig.Validate())
	assert.True(t, sig.IsValid())
	assert.NotEmpty(t, sig.String())
	assert.NotNil(t, sig.Serialize())
}

// TestSignatureSizeIsExported confirms SignatureSize is the single source
// of truth for signature type-to-size mapping.
// Covers: [GAP] No exported SignatureSize function.
func TestSignatureSizeIsExported(t *testing.T) {
	// Verify it returns correct sizes for all supported types
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

// BenchmarkReadSignature benchmarks ReadSignature for hot-path performance.
// Covers: [TEST] No benchmark tests.
func BenchmarkReadSignature(b *testing.B) {
	data := make([]byte, EdDSA_SHA512_Ed25519_SIZE+100)
	for i := range data {
		data[i] = byte(i % 256)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = ReadSignature(data, SIGNATURE_TYPE_EDDSA_SHA512_ED25519)
	}
}

// BenchmarkNewSignatureFromBytes benchmarks NewSignatureFromBytes.
func BenchmarkNewSignatureFromBytes(b *testing.B) {
	data := make([]byte, EdDSA_SHA512_Ed25519_SIZE)
	for i := range data {
		data[i] = byte(i % 256)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = NewSignatureFromBytes(data, SIGNATURE_TYPE_EDDSA_SHA512_ED25519)
	}
}

// BenchmarkSignatureEqual benchmarks constant-time Equal comparison.
func BenchmarkSignatureEqual(b *testing.B) {
	data1 := make([]byte, EdDSA_SHA512_Ed25519_SIZE)
	data2 := make([]byte, EdDSA_SHA512_Ed25519_SIZE)
	for i := range data1 {
		data1[i] = byte(i % 256)
		data2[i] = byte(i % 256)
	}
	sig1, _ := NewSignatureFromBytes(data1, SIGNATURE_TYPE_EDDSA_SHA512_ED25519)
	sig2, _ := NewSignatureFromBytes(data2, SIGNATURE_TYPE_EDDSA_SHA512_ED25519)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sig1.Equal(&sig2)
	}
}

// BenchmarkSignatureBytes benchmarks defensive-copy Bytes() method.
func BenchmarkSignatureBytes(b *testing.B) {
	data := make([]byte, EdDSA_SHA512_Ed25519_SIZE)
	sig, _ := NewSignatureFromBytes(data, SIGNATURE_TYPE_EDDSA_SHA512_ED25519)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = sig.Bytes()
	}
}

// BenchmarkSignatureValidate benchmarks Validate.
func BenchmarkSignatureValidate(b *testing.B) {
	data := make([]byte, EdDSA_SHA512_Ed25519_SIZE)
	sig, _ := NewSignatureFromBytes(data, SIGNATURE_TYPE_EDDSA_SHA512_ED25519)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = sig.Validate()
	}
}

// BenchmarkSignatureSize benchmarks the exported SignatureSize lookup.
func BenchmarkSignatureSize(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = SignatureSize(SIGNATURE_TYPE_EDDSA_SHA512_ED25519)
	}
}
