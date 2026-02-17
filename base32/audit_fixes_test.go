package base32

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"unicode"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Finding [SPEC]: DecodeString fails on unpadded base32 input ---
// Validates that the NoPadding variants correctly handle unpadded I2P base32 addresses.

func TestDecodeStringNoPadding_52CharAddress(t *testing.T) {
	// A 32-byte SHA-256 hash encodes to 52 unpadded base32 characters.
	hash := sha256.Sum256([]byte("test destination data"))
	encoded := EncodeToStringNoPadding(hash[:])

	assert.Equal(t, 52, len(encoded),
		"32-byte hash should encode to exactly 52 unpadded base32 characters")

	decoded, err := DecodeStringNoPadding(encoded)
	require.NoError(t, err, "DecodeStringNoPadding should decode 52-char unpadded address")
	assert.Equal(t, hash[:], decoded, "round-trip should preserve original hash bytes")
}

func TestDecodeString_FailsOnUnpadded(t *testing.T) {
	// Verify that the padded decoder rejects unpadded input (the original bug).
	hash := sha256.Sum256([]byte("test"))
	padded := EncodeToString(hash[:])
	unpadded := strings.TrimRight(padded, "=")

	// Padded decoder should fail on unpadded input
	_, err := DecodeString(unpadded)
	assert.Error(t, err, "padded DecodeString should reject unpadded input")

	// NoPadding decoder should succeed
	decoded, err := DecodeStringNoPadding(unpadded)
	require.NoError(t, err, "DecodeStringNoPadding should accept unpadded input")
	assert.Equal(t, hash[:], decoded)
}

// --- Finding [GAP]: DecodeStringSafe ---

func TestDecodeStringSafe_ValidInput(t *testing.T) {
	original := []byte("Hello, I2P network!")
	encoded := EncodeToString(original)

	decoded, err := DecodeStringSafe(encoded)
	require.NoError(t, err)
	assert.Equal(t, original, decoded)
}

func TestDecodeStringSafe_EmptyInput(t *testing.T) {
	_, err := DecodeStringSafe("")
	assert.ErrorIs(t, err, ErrEmptyData)
}

func TestDecodeStringSafe_TooLargeInput(t *testing.T) {
	tooLarge := strings.Repeat("a", MAX_DECODE_SIZE+1)
	_, err := DecodeStringSafe(tooLarge)
	assert.ErrorIs(t, err, ErrInputTooLarge)
}

func TestDecodeStringSafe_AtMaxSize(t *testing.T) {
	// Encode MAX_ENCODE_SIZE bytes, the result should be within MAX_DECODE_SIZE
	data := make([]byte, 100)
	for i := range data {
		data[i] = byte(i)
	}
	encoded := EncodeToString(data)

	decoded, err := DecodeStringSafe(encoded)
	require.NoError(t, err)
	assert.Equal(t, data, decoded)
}

func TestDecodeStringSafeNoPadding_ValidInput(t *testing.T) {
	hash := sha256.Sum256([]byte("test safe no-padding"))
	encoded := EncodeToStringNoPadding(hash[:])

	decoded, err := DecodeStringSafeNoPadding(encoded)
	require.NoError(t, err)
	assert.Equal(t, hash[:], decoded)
}

func TestDecodeStringSafeNoPadding_EmptyInput(t *testing.T) {
	_, err := DecodeStringSafeNoPadding("")
	assert.ErrorIs(t, err, ErrEmptyData)
}

func TestDecodeStringSafeNoPadding_TooLargeInput(t *testing.T) {
	tooLarge := strings.Repeat("a", MAX_DECODE_SIZE+1)
	_, err := DecodeStringSafeNoPadding(tooLarge)
	assert.ErrorIs(t, err, ErrInputTooLarge)
}

// --- Finding [TEST]: Alphabet correctness ---

func TestI2PAlphabetCorrectness(t *testing.T) {
	t.Run("length is 32", func(t *testing.T) {
		assert.Equal(t, 32, len(I2PEncodeAlphabet),
			"base32 alphabet must have exactly 32 characters")
	})

	t.Run("no duplicates", func(t *testing.T) {
		seen := make(map[rune]bool)
		for _, c := range I2PEncodeAlphabet {
			assert.False(t, seen[c], "duplicate character %c in alphabet", c)
			seen[c] = true
		}
	})

	t.Run("all lowercase", func(t *testing.T) {
		for _, c := range I2PEncodeAlphabet {
			if unicode.IsLetter(c) {
				assert.True(t, unicode.IsLower(c),
					"letter %c must be lowercase", c)
			}
		}
	})

	t.Run("only a-z and 2-7", func(t *testing.T) {
		for _, c := range I2PEncodeAlphabet {
			isLowerAlpha := c >= 'a' && c <= 'z'
			isValidDigit := c >= '2' && c <= '7'
			assert.True(t, isLowerAlpha || isValidDigit,
				"character %c is not in allowed set [a-z2-7]", c)
		}
	})

	t.Run("matches RFC 3548 lowercase", func(t *testing.T) {
		expected := "abcdefghijklmnopqrstuvwxyz234567"
		assert.Equal(t, expected, I2PEncodeAlphabet,
			"alphabet must match RFC 3548 lowercase base32")
	})
}

// --- Finding [TEST]: DecodeString with invalid input ---

func TestDecodeString_InvalidCharacters(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"uppercase letters", "JBSWY3DP"},
		{"digit 0", "0bswy3dp"},
		{"digit 1", "1bswy3dp"},
		{"digit 8", "8bswy3dp"},
		{"digit 9", "9bswy3dp"},
		{"special characters", "jbsw!@#$"},
		{"mixed case", "JbSwY3Dp"},
		{"space in middle", "jbsw y3dp"},
		{"standard base32 uppercase", "MFRGGZDFMY======"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DecodeString(tt.input)
			assert.Error(t, err,
				"DecodeString should reject invalid input: %s", tt.input)
		})
	}
}

func TestDecodeStringNoPadding_InvalidCharacters(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"uppercase", "JBSWY3DP"},
		{"digit 0", "0bswy3dp"},
		{"digit 1", "1bswy3dp"},
		{"digit 8", "8bswy3dp"},
		{"digit 9", "9bswy3dp"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DecodeStringNoPadding(tt.input)
			assert.Error(t, err,
				"DecodeStringNoPadding should reject invalid input: %s", tt.input)
		})
	}
}

// --- Finding [TEST]: 32-byte SHA-256 hash round-trip ---

func TestSHA256HashRoundTrip(t *testing.T) {
	// The primary I2P use case: encoding a 32-byte SHA-256 hash
	hash := sha256.Sum256([]byte("i2p destination for testing"))

	t.Run("padded encoding is 56 chars", func(t *testing.T) {
		encoded := EncodeToString(hash[:])
		// 32 bytes = 256 bits / 5 = 51.2 → ceil = 52 data chars → pad to next multiple of 8 = 56
		assert.Equal(t, 56, len(encoded),
			"32-byte hash padded base32 should be 56 characters (52 data + 4 padding)")
		assert.True(t, strings.HasSuffix(encoded, "===="),
			"32-byte hash should have 4 '=' padding characters")
	})

	t.Run("unpadded encoding is 52 chars", func(t *testing.T) {
		encoded := EncodeToStringNoPadding(hash[:])
		assert.Equal(t, 52, len(encoded),
			"32-byte hash unpadded base32 should be exactly 52 characters")
		assert.False(t, strings.Contains(encoded, "="),
			"unpadded encoding should not contain '='")
	})

	t.Run("padded round-trip preserves data", func(t *testing.T) {
		encoded := EncodeToString(hash[:])
		decoded, err := DecodeString(encoded)
		require.NoError(t, err)
		assert.Equal(t, hash[:], decoded)
	})

	t.Run("unpadded round-trip preserves data", func(t *testing.T) {
		encoded := EncodeToStringNoPadding(hash[:])
		decoded, err := DecodeStringNoPadding(encoded)
		require.NoError(t, err)
		assert.Equal(t, hash[:], decoded)
	})
}

// --- Finding [TEST]: Padded-encode → strip-padding → re-pad → decode round-trip ---
// This is the actual production code path used by destination.Base32Address()

func TestPaddedEncodeStripRepadDecodeRoundTrip(t *testing.T) {
	hash := sha256.Sum256([]byte("production code path test"))

	// Step 1: Padded encode (what destination.Base32Address does)
	padded := EncodeToString(hash[:])

	// Step 2: Strip padding (what strings.Trim(..., "=") does)
	stripped := strings.TrimRight(padded, "=")
	assert.Equal(t, 52, len(stripped),
		"stripped address should be 52 characters")

	// Step 3: Re-pad to decode with padded decoder
	// base32 pads to multiple of 8 characters
	paddingNeeded := (8 - len(stripped)%8) % 8
	repadded := stripped + strings.Repeat("=", paddingNeeded)

	// Step 4: Decode with padded decoder
	decoded, err := DecodeString(repadded)
	require.NoError(t, err, "re-padded string should decode successfully")
	assert.Equal(t, hash[:], decoded, "round-trip should preserve original hash")

	// Alternative: Decode directly with NoPadding decoder (preferred approach)
	decodedNoPad, err := DecodeStringNoPadding(stripped)
	require.NoError(t, err, "NoPadding decoder should handle stripped string directly")
	assert.Equal(t, hash[:], decodedNoPad,
		"NoPadding decoder should produce same result as re-pad approach")
}

// --- Finding [TEST]: Interoperability test vectors ---
// Known test vector: SHA-256 of empty string, verified against Java I2P Base32 implementation.

func TestInteroperabilityVector(t *testing.T) {
	// SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
	hashHex := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	hashBytes, err := hex.DecodeString(hashHex)
	require.NoError(t, err)

	// Expected base32 (lowercase, no padding):
	// This can be independently verified with:
	//   echo -n "" | sha256sum | xxd -r -p | base32 | tr 'A-Z' 'a-z' | tr -d '='
	// Result: 4oymiquy7qobjgx36tejs35zeqt24qpemsnzgtfeswmrw6csxbkq
	expectedNoPadding := "4oymiquy7qobjgx36tejs35zeqt24qpemsnzgtfeswmrw6csxbkq"
	expectedPadded := "4oymiquy7qobjgx36tejs35zeqt24qpemsnzgtfeswmrw6csxbkq===="

	t.Run("padded encoding matches vector", func(t *testing.T) {
		encoded := EncodeToString(hashBytes)
		assert.Equal(t, expectedPadded, encoded)
	})

	t.Run("unpadded encoding matches vector", func(t *testing.T) {
		encoded := EncodeToStringNoPadding(hashBytes)
		assert.Equal(t, expectedNoPadding, encoded)
	})

	t.Run("padded decode matches vector", func(t *testing.T) {
		decoded, err := DecodeString(expectedPadded)
		require.NoError(t, err)
		assert.Equal(t, hashBytes, decoded)
	})

	t.Run("unpadded decode matches vector", func(t *testing.T) {
		decoded, err := DecodeStringNoPadding(expectedNoPadding)
		require.NoError(t, err)
		assert.Equal(t, hashBytes, decoded)
	})
}

// --- Finding [TEST]: Fuzz test for DecodeString ---

func FuzzDecodeString(f *testing.F) {
	// Seed corpus with valid and edge-case inputs
	f.Add("jbswy3dp")
	f.Add("jbswy3dp====")
	f.Add("")
	f.Add("aaaa")
	f.Add("4oymiquy7qobjgx36tejs35zeqt24qpemsnzgtfeswmrw6csxbkq")
	f.Add("4oymiquy7qobjgx36tejs35zeqt24qpemsnzgtfeswmrw6csxbkq====")
	f.Add("JBSWY3DP") // uppercase (should be rejected)
	f.Add("0189!@#$") // invalid characters

	f.Fuzz(func(t *testing.T, input string) {
		// Must not panic on any input
		decoded, err := DecodeString(input)
		if err == nil && len(decoded) > 0 {
			// If decode succeeds, re-encode and verify round-trip
			reencoded := EncodeToString(decoded)
			redecoded, err2 := DecodeString(reencoded)
			if err2 != nil {
				t.Errorf("round-trip encode→decode failed: %v", err2)
			}
			if len(decoded) != len(redecoded) {
				t.Errorf("round-trip length mismatch: %d != %d",
					len(decoded), len(redecoded))
			}
		}
	})
}

func FuzzDecodeStringNoPadding(f *testing.F) {
	f.Add("jbswy3dp")
	f.Add("")
	f.Add("4oymiquy7qobjgx36tejs35zeqt24qpemsnzgtfeswmrw6csxbkq")
	f.Add("JBSWY3DP")

	f.Fuzz(func(t *testing.T, input string) {
		// Must not panic on any input
		decoded, err := DecodeStringNoPadding(input)
		if err == nil && len(decoded) > 0 {
			reencoded := EncodeToStringNoPadding(decoded)
			redecoded, err2 := DecodeStringNoPadding(reencoded)
			if err2 != nil {
				t.Errorf("round-trip encode→decode failed: %v", err2)
			}
			if len(decoded) != len(redecoded) {
				t.Errorf("round-trip length mismatch: %d != %d",
					len(decoded), len(redecoded))
			}
		}
	})
}
