package signature

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSignatureEqual tests the Equal() method for Signature comparison.
// Covers: [GAP] No Equal() method for Signature comparison.
func TestSignatureEqual(t *testing.T) {
	t.Run("equal signatures", func(t *testing.T) {
		data1 := []byte{0x01, 0x02, 0x03, 0x04}
		data2 := []byte{0x01, 0x02, 0x03, 0x04}
		sig1 := NewSignatureFromBytes(data1, SIGNATURE_TYPE_EDDSA_SHA512_ED25519)
		sig2 := NewSignatureFromBytes(data2, SIGNATURE_TYPE_EDDSA_SHA512_ED25519)
		assert.True(t, sig1.Equal(&sig2))
	})

	t.Run("different data", func(t *testing.T) {
		data1 := []byte{0x01, 0x02, 0x03, 0x04}
		data2 := []byte{0x01, 0x02, 0x03, 0x05}
		sig1 := NewSignatureFromBytes(data1, SIGNATURE_TYPE_EDDSA_SHA512_ED25519)
		sig2 := NewSignatureFromBytes(data2, SIGNATURE_TYPE_EDDSA_SHA512_ED25519)
		assert.False(t, sig1.Equal(&sig2))
	})

	t.Run("different types", func(t *testing.T) {
		data := make([]byte, 64)
		sig1 := NewSignatureFromBytes(data, SIGNATURE_TYPE_EDDSA_SHA512_ED25519)
		sig2 := NewSignatureFromBytes(data, SIGNATURE_TYPE_ECDSA_SHA256_P256)
		assert.False(t, sig1.Equal(&sig2))
	})

	t.Run("different lengths", func(t *testing.T) {
		data1 := make([]byte, 40)
		data2 := make([]byte, 64)
		sig1 := NewSignatureFromBytes(data1, SIGNATURE_TYPE_DSA_SHA1)
		sig2 := NewSignatureFromBytes(data2, SIGNATURE_TYPE_DSA_SHA1)
		assert.False(t, sig1.Equal(&sig2))
	})

	t.Run("nil other", func(t *testing.T) {
		data := []byte{0x01, 0x02}
		sig := NewSignatureFromBytes(data, SIGNATURE_TYPE_EDDSA_SHA512_ED25519)
		assert.False(t, sig.Equal(nil))
	})

	t.Run("both empty data", func(t *testing.T) {
		sig1 := NewSignatureFromBytes([]byte{}, SIGNATURE_TYPE_EDDSA_SHA512_ED25519)
		sig2 := NewSignatureFromBytes([]byte{}, SIGNATURE_TYPE_EDDSA_SHA512_ED25519)
		assert.True(t, sig1.Equal(&sig2))
	})
}

// TestSignatureRoundTrip tests full lifecycle: create → serialize → reconstruct.
// Covers: [TEST] No round-trip serialization test.
func TestSignatureRoundTrip(t *testing.T) {
	testCases := []struct {
		name    string
		sigType int
		size    int
	}{
		{"DSA_SHA1", SIGNATURE_TYPE_DSA_SHA1, DSA_SHA1_SIZE},
		{"ECDSA_SHA256_P256", SIGNATURE_TYPE_ECDSA_SHA256_P256, ECDSA_SHA256_P256_SIZE},
		{"ECDSA_SHA384_P384", SIGNATURE_TYPE_ECDSA_SHA384_P384, ECDSA_SHA384_P384_SIZE},
		{"ECDSA_SHA512_P521", SIGNATURE_TYPE_ECDSA_SHA512_P521, ECDSA_SHA512_P521_SIZE},
		{"RSA_SHA256_2048", SIGNATURE_TYPE_RSA_SHA256_2048, RSA_SHA256_2048_SIZE},
		{"RSA_SHA384_3072", SIGNATURE_TYPE_RSA_SHA384_3072, RSA_SHA384_3072_SIZE},
		{"RSA_SHA512_4096", SIGNATURE_TYPE_RSA_SHA512_4096, RSA_SHA512_4096_SIZE},
		{"EdDSA_SHA512_Ed25519", SIGNATURE_TYPE_EDDSA_SHA512_ED25519, EdDSA_SHA512_Ed25519_SIZE},
		{"EdDSA_SHA512_Ed25519ph", SIGNATURE_TYPE_EDDSA_SHA512_ED25519PH, EdDSA_SHA512_Ed25519ph_SIZE},
		{"RedDSA_SHA512_Ed25519", SIGNATURE_TYPE_REDDSA_SHA512_ED25519, RedDSA_SHA512_Ed25519_SIZE},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create original data with non-trivial pattern
			original := make([]byte, tc.size+10) // extra bytes for remainder
			for i := range original {
				original[i] = byte((i * 37) ^ 0xAB)
			}

			// Create signature via ReadSignature
			sig1, remainder, err := ReadSignature(original, tc.sigType)
			require.NoError(t, err)
			assert.Len(t, remainder, 10)

			// Extract bytes and reconstruct
			bytes := sig1.Bytes()
			sig2 := NewSignatureFromBytes(bytes, tc.sigType)

			// Verify equality
			assert.True(t, sig1.Equal(&sig2),
				"round-trip should produce equal signatures")
			assert.Equal(t, sig1.Type(), sig2.Type())
			assert.Equal(t, sig1.Len(), sig2.Len())
			assert.Equal(t, sig1.Bytes(), sig2.Bytes())

			// Reconstruct again via ReadSignature on extracted bytes
			padded := append(bytes, 0xDE, 0xAD) // add remainder
			sig3, rem3, err := ReadSignature(padded, tc.sigType)
			require.NoError(t, err)
			assert.Equal(t, []byte{0xDE, 0xAD}, rem3)
			assert.True(t, sig1.Equal(&sig3))
		})
	}
}

// TestSignatureBufferIsolation verifies that ReadSignature copies data
// and doesn't alias the caller's buffer.
// Covers: [BUG] extractSignatureData aliases input slice — validates fix.
func TestSignatureBufferIsolation(t *testing.T) {
	buf := make([]byte, EdDSA_SHA512_Ed25519_SIZE)
	for i := range buf {
		buf[i] = byte(i)
	}

	sig, _, err := ReadSignature(buf, SIGNATURE_TYPE_EDDSA_SHA512_ED25519)
	require.NoError(t, err)

	// Save original signature bytes
	originalBytes := make([]byte, len(sig.Bytes()))
	copy(originalBytes, sig.Bytes())

	// Mutate the original buffer (simulating buffer reuse)
	for i := range buf {
		buf[i] = 0xFF
	}

	// Signature bytes must NOT have changed
	assert.Equal(t, originalBytes, sig.Bytes(),
		"signature data should be isolated from caller's buffer")
}

// TestSignatureStringFormat tests the String() output format.
// Covers: [TEST] No test for String() output format.
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
			sig := NewSignatureFromBytes(data, tc.sigType)
			assert.Equal(t, tc.expected, sig.String())
		})
	}

	// Also test with zero-length data (edge case)
	t.Run("empty data", func(t *testing.T) {
		sig := NewSignatureFromBytes([]byte{}, 7)
		assert.Equal(t, "Signature{type: 7, length: 0}", sig.String())
	})
}

// TestNewSignatureFromBytesNoValidation confirms that NewSignatureFromBytes
// does not validate data length against type.
// Covers: [GAP] NewSignatureFromBytes bypasses validation.
func TestNewSignatureFromBytesNoValidation(t *testing.T) {
	// Create with mismatched data size (EdDSA expects 64 but give 10)
	data := make([]byte, 10)
	sig := NewSignatureFromBytes(data, SIGNATURE_TYPE_EDDSA_SHA512_ED25519)

	// Should construct without error
	assert.Equal(t, SIGNATURE_TYPE_EDDSA_SHA512_ED25519, sig.Type())
	assert.Equal(t, 10, sig.Len())

	// But Validate() should catch the mismatch
	err := sig.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "signature data size mismatch")
}

// TestDeprecatedP512Alias verifies the deprecated ECDSA_SHA512_P512_SIZE
// alias still works and equals the correctly-named constant.
// Covers: [QUALITY] Constant naming error P512 → P521.
func TestDeprecatedP512Alias(t *testing.T) {
	assert.Equal(t, ECDSA_SHA512_P521_SIZE, ECDSA_SHA512_P512_SIZE,
		"deprecated alias should equal the correctly-named constant")
	assert.Equal(t, 132, ECDSA_SHA512_P521_SIZE,
		"ECDSA_SHA512_P521_SIZE should be 132 bytes per spec")
}

// FuzzReadSignature exercises ReadSignature with adversarial input.
// Covers: [TEST] No fuzz testing for ReadSignature.
func FuzzReadSignature(f *testing.F) {
	// Seed corpus with representative inputs
	sigTypes := []int{
		SIGNATURE_TYPE_DSA_SHA1, SIGNATURE_TYPE_ECDSA_SHA256_P256,
		SIGNATURE_TYPE_ECDSA_SHA384_P384, SIGNATURE_TYPE_ECDSA_SHA512_P521,
		SIGNATURE_TYPE_RSA_SHA256_2048, SIGNATURE_TYPE_RSA_SHA384_3072,
		SIGNATURE_TYPE_RSA_SHA512_4096, SIGNATURE_TYPE_EDDSA_SHA512_ED25519,
		SIGNATURE_TYPE_EDDSA_SHA512_ED25519PH, SIGNATURE_TYPE_REDDSA_SHA512_ED25519,
	}

	for _, st := range sigTypes {
		// Valid-length input
		size, _ := getSignatureLength(st)
		data := make([]byte, size)
		f.Add(data, st)
		// Truncated input
		if size > 0 {
			f.Add(data[:size/2], st)
		}
	}
	// Edge cases
	f.Add([]byte{}, 0)
	f.Add([]byte{}, -1)
	f.Add([]byte{}, 1000)
	f.Add([]byte(nil), 7)

	f.Fuzz(func(t *testing.T, data []byte, sigType int) {
		sig, remainder, err := ReadSignature(data, sigType)
		if err != nil {
			// On error, signature should be zero-value
			assert.Equal(t, 0, sig.Len())
			return
		}

		// On success: signature + remainder must account for all input
		assert.Equal(t, len(data), sig.Len()+len(remainder),
			fmt.Sprintf("sig.Len()=%d + remainder=%d should equal input=%d",
				sig.Len(), len(remainder), len(data)))
		assert.Equal(t, sigType, sig.Type())

		// Validate must pass for successfully-read signatures
		err = sig.Validate()
		assert.NoError(t, err)
	})
}
