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
			sig2, err := NewSignatureFromBytes(bytes, tc.sigType)
			require.NoError(t, err)

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
			sig, err := NewSignatureFromBytes(data, tc.sigType)
			require.NoError(t, err)
			assert.Equal(t, tc.expected, sig.String())
		})
	}

	// Also test with empty data (edge case - now errors)
	t.Run("empty data rejected", func(t *testing.T) {
		_, err := NewSignatureFromBytes([]byte{}, 7)
		assert.Error(t, err)
	})
}

// TestNewSignatureFromBytesValidation confirms that NewSignatureFromBytes
// now validates data length against type (BUG fix).
// Covers: [BUG] NewSignatureFromBytes allowed invalid construction — validates fix.
func TestNewSignatureFromBytesValidation(t *testing.T) {
	// Create with mismatched data size (EdDSA expects 64 but give 10)
	data := make([]byte, 10)
	_, err := NewSignatureFromBytes(data, SIGNATURE_TYPE_EDDSA_SHA512_ED25519)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not match expected")

	// Create with correct data size should succeed
	correctData := make([]byte, EdDSA_SHA512_Ed25519_SIZE)
	sig, err := NewSignatureFromBytes(correctData, SIGNATURE_TYPE_EDDSA_SHA512_ED25519)
	require.NoError(t, err)
	assert.Equal(t, SIGNATURE_TYPE_EDDSA_SHA512_ED25519, sig.Type())
	assert.Equal(t, EdDSA_SHA512_Ed25519_SIZE, sig.Len())

	// Validate must also pass
	err = sig.Validate()
	require.NoError(t, err)

	// Invalid signature type should be rejected
	_, err = NewSignatureFromBytes(make([]byte, 64), 9999)
	require.Error(t, err)

	// Negative sigType should be rejected (out of uint16 range)
	_, err = NewSignatureFromBytes(make([]byte, 40), -1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "out of valid range")

	// sigType > 65535 should be rejected
	_, err = NewSignatureFromBytes(make([]byte, 40), 70000)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "out of valid range")
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

// TestSignatureSizeExported tests the exported SignatureSize() function.
// Covers: [BUG] No exported function to query signature size by type.
func TestSignatureSizeExported(t *testing.T) {
	testCases := []struct {
		sigType  int
		expected int
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
		size, err := SignatureSize(tc.sigType)
		assert.NoError(t, err)
		assert.Equal(t, tc.expected, size, "SignatureSize(%d)", tc.sigType)
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

// TestGOSTReservedTypes tests that GOST R 3410-2012 signature types 9 and 10
// are recognized as reserved but return distinct errors.
// Covers: [SPEC] GOST types 9/10 reserved per Proposal 134 but unhandled.
func TestGOSTReservedTypes(t *testing.T) {
	// Type 9: GOST R 3410-2012-512
	_, err := SignatureSize(SIGNATURE_TYPE_GOST_R3410_2012_512)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "reserved")
	assert.Contains(t, err.Error(), "GOST")

	// Type 10: GOST R 3410-2012-1024
	_, err = SignatureSize(SIGNATURE_TYPE_GOST_R3410_2012_1024)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "reserved")
	assert.Contains(t, err.Error(), "GOST")

	// NewSignatureFromBytes should also reject GOST types
	_, err = NewSignatureFromBytes(make([]byte, GOST_R3410_2012_512_SIZE), SIGNATURE_TYPE_GOST_R3410_2012_512)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "reserved")

	_, err = NewSignatureFromBytes(make([]byte, GOST_R3410_2012_1024_SIZE), SIGNATURE_TYPE_GOST_R3410_2012_1024)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "reserved")
}

// TestSigTypeRangeValidation tests that sigType values outside uint16 range
// (0-65535) are rejected by all entry points.
// Covers: [BUG] sigType field uses int but spec defines uint16 (0-65535).
func TestSigTypeRangeValidation(t *testing.T) {
	t.Run("negative sigType rejected by SignatureSize", func(t *testing.T) {
		_, err := SignatureSize(-1)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "out of valid range")
	})

	t.Run("negative sigType rejected by NewSignatureFromBytes", func(t *testing.T) {
		_, err := NewSignatureFromBytes(make([]byte, 40), -1)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "out of valid range")
	})

	t.Run("sigType > 65535 rejected by SignatureSize", func(t *testing.T) {
		_, err := SignatureSize(65536)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "out of valid range")
	})

	t.Run("sigType > 65535 rejected by NewSignatureFromBytes", func(t *testing.T) {
		_, err := NewSignatureFromBytes(make([]byte, 40), 65536)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "out of valid range")
	})

	t.Run("sigType 0 is valid (DSA_SHA1)", func(t *testing.T) {
		size, err := SignatureSize(0)
		require.NoError(t, err)
		assert.Equal(t, DSA_SHA1_SIZE, size)
	})

	t.Run("sigType 65535 is reserved future", func(t *testing.T) {
		_, err := SignatureSize(65535)
		require.Error(t, err)
		// 65535 is reserved for future expansion
	})

	t.Run("MLDSA range 12-20 reserved", func(t *testing.T) {
		for sigType := 12; sigType <= 20; sigType++ {
			_, err := SignatureSize(sigType)
			require.Error(t, err, "type %d should be reserved", sigType)
			assert.Contains(t, err.Error(), "reserved", "type %d", sigType)
		}
	})

	t.Run("experimental range 65280-65534", func(t *testing.T) {
		_, err := SignatureSize(65280)
		require.Error(t, err)
		// Experimental types are not supported
	})
}
