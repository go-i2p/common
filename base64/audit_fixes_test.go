package base64

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Finding: [TEST] Alphabet correctness (constants.go:11) ---

// TestI2PAlphabetLength verifies the I2P alphabet is exactly 64 characters.
func TestI2PAlphabetLength(t *testing.T) {
	assert.Equal(t, 64, len(I2PEncodeAlphabet),
		"I2P base64 alphabet must be exactly 64 characters")
}

// TestI2PAlphabetUnique verifies the I2P alphabet has no duplicate characters.
func TestI2PAlphabetUnique(t *testing.T) {
	seen := make(map[byte]int)
	for i := 0; i < len(I2PEncodeAlphabet); i++ {
		ch := I2PEncodeAlphabet[i]
		if prev, ok := seen[ch]; ok {
			t.Fatalf("duplicate character %q at positions %d and %d", ch, prev, i)
		}
		seen[ch] = i
	}
}

// TestI2PAlphabetSubstitutions verifies the I2P-specific character substitutions:
// position 62 = '-' (replaces '+'), position 63 = '~' (replaces '/').
func TestI2PAlphabetSubstitutions(t *testing.T) {
	assert.Equal(t, byte('-'), I2PEncodeAlphabet[62],
		"position 62 must be '-' (I2P substitute for '+')")
	assert.Equal(t, byte('~'), I2PEncodeAlphabet[63],
		"position 63 must be '~' (I2P substitute for '/')")
}

// TestI2PAlphabetStandardPrefix verifies A-Z, a-z, 0-9 are in standard positions.
func TestI2PAlphabetStandardPrefix(t *testing.T) {
	expected := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	assert.Equal(t, expected, I2PEncodeAlphabet[:62],
		"positions 0-61 must be the standard base64 A-Za-z0-9 characters")
}

// TestI2PAlphabetDoesNotContainStandardChars verifies '+' and '/' are NOT in the alphabet.
func TestI2PAlphabetDoesNotContainStandardChars(t *testing.T) {
	assert.NotContains(t, I2PEncodeAlphabet, "+",
		"I2P alphabet must not contain '+'")
	assert.NotContains(t, I2PEncodeAlphabet, "/",
		"I2P alphabet must not contain '/'")
}

// --- Finding: [TEST] Invalid input characters (utils.go:33) ---

// TestDecodeStringRejectsStandardBase64Chars verifies that standard base64 characters
// '+' and '/' that are NOT in the I2P alphabet cause decode errors.
func TestDecodeStringRejectsStandardBase64Chars(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"plus sign", "SGVsbG8+"},
		{"forward slash", "SGVsbG8/"},
		{"both standard chars", "+/+/"},
		{"mixed with valid", "AAAA+BBB"},
		{"slash in middle", "AA/A"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DecodeString(tt.input)
			assert.Error(t, err, "decode should reject standard base64 char in: %q", tt.input)
		})
	}
}

// --- Finding: [TEST] Malformed padding, truncated input, whitespace (utils.go:33) ---

// TestDecodeStringMalformedInput verifies DecodeString handles edge cases correctly.
func TestDecodeStringMalformedInput(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		expectErr bool
	}{
		// Malformed padding
		{"single padding where none expected", "SGVS=", true},
		{"triple padding", "SGV===", true},
		{"five paddings", "S=====", true},
		// Truncated input (not a multiple of 4 with no valid padding)
		{"single char", "A", true},
		{"two chars no padding", "SG", true},
		{"three chars no padding", "SGV", true},
		// Whitespace handling:
		// Go's encoding/base64 strips \n and \r during decode (standard behavior),
		// but rejects spaces, tabs, and other whitespace.
		{"embedded space", "SGVs bG8=", true},
		{"embedded newline (stripped by Go)", "SGVs\nbG8=", false},
		{"embedded tab", "SGVs\tbG8=", true},
		{"leading space", " SGVsbG8=", true},
		{"trailing space", "SGVsbG8= ", true},
		// Empty/invalid
		{"empty string (valid per Go stdlib)", "", false},
		{"only padding", "====", true},
		// Valid cases for comparison
		{"valid with padding", "SGVsbG8=", false},
		{"valid no padding needed", "SGVsbG8w", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DecodeString(tt.input)
			if tt.expectErr {
				assert.Error(t, err, "decode should fail for: %q", tt.input)
			} else {
				assert.NoError(t, err, "decode should succeed for: %q", tt.input)
			}
		})
	}
}

// --- Finding: [TEST] Interoperability test vectors (base64_test.go:11) ---

// TestInteropTestVectors verifies encoding/decoding against known test vectors
// that exercise the I2P-specific character substitutions (- for +, ~ for /).
func TestInteropTestVectors(t *testing.T) {
	tests := []struct {
		name    string
		raw     []byte
		encoded string
		usesI2P bool // true if the encoded form contains '-' or '~'
	}{
		{
			name:    "simple ASCII (no substitution)",
			raw:     []byte("Hello"),
			encoded: "SGVsbG8=",
			usesI2P: false,
		},
		{
			name:    "all 0xFF bytes trigger ~ (position 63)",
			raw:     []byte{0xff, 0xff, 0xff},
			encoded: "~~~~",
			usesI2P: true,
		},
		{
			name:    "0xFB,0xFF,0xFE triggers both - and ~",
			raw:     []byte{0xfb, 0xff, 0xfe},
			encoded: "-~~-",
			usesI2P: true,
		},
		{
			name:    "single 0xFF byte",
			raw:     []byte{0xff},
			encoded: "~w==",
			usesI2P: true,
		},
		{
			name:    "bytes producing - at position 62",
			raw:     []byte{0xf8},
			encoded: "-A==",
			usesI2P: true,
		},
		{
			name:    "empty input",
			raw:     []byte{},
			encoded: "",
			usesI2P: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test encode
			encoded := EncodeToString(tt.raw)
			assert.Equal(t, tt.encoded, encoded, "encoding mismatch")

			// Cross-check: if I2P chars present, verify standard base64 differs
			if tt.usesI2P {
				stdEncoded := base64.StdEncoding.EncodeToString(tt.raw)
				assert.NotEqual(t, stdEncoded, encoded,
					"I2P encoding should differ from standard when using substituted chars")
			}

			// Test decode (skip empty)
			if len(tt.encoded) > 0 {
				decoded, err := DecodeString(tt.encoded)
				require.NoError(t, err, "decode should succeed")
				assert.Equal(t, tt.raw, decoded, "round-trip decode mismatch")
			}
		})
	}
}

// TestInteropStandardBase64Equivalence verifies that for inputs not using positions 62/63,
// I2P base64 produces identical output to standard base64.
func TestInteropStandardBase64Equivalence(t *testing.T) {
	// These inputs only produce base64 chars at positions 0-61 (A-Za-z0-9)
	inputs := [][]byte{
		[]byte("Hello, World!"),
		[]byte("The quick brown fox"),
		{0x00, 0x00, 0x00},
		{0x10, 0x20, 0x30},
	}

	for _, input := range inputs {
		i2pEnc := EncodeToString(input)
		stdEnc := base64.StdEncoding.EncodeToString(input)
		// For these inputs, check they don't contain substituted chars
		if !strings.ContainsAny(stdEnc, "+/") {
			assert.Equal(t, stdEnc, i2pEnc,
				"should match standard base64 when no substitution needed")
		}
	}
}

// --- Finding: [GAP] DecodeStringSafe (utils.go:38) ---

// TestDecodeStringSafe_ValidInput tests successful decoding with valid input.
func TestDecodeStringSafe_ValidInput(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []byte
	}{
		{"simple hello", "SGVsbG8=", []byte("Hello")},
		{"I2P chars", "~~~~", []byte{0xff, 0xff, 0xff}},
		{"short input", "QQ==", []byte("A")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := DecodeStringSafe(tt.input)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

// TestDecodeStringSafe_EmptyString tests that empty input returns ErrEmptyString.
func TestDecodeStringSafe_EmptyString(t *testing.T) {
	decoded, err := DecodeStringSafe("")
	assert.ErrorIs(t, err, ErrEmptyString)
	assert.Nil(t, decoded)
}

// TestDecodeStringSafe_TooLarge tests that oversized input returns ErrStringTooLarge.
func TestDecodeStringSafe_TooLarge(t *testing.T) {
	tooLarge := strings.Repeat("A", MAX_DECODE_SIZE+1)
	decoded, err := DecodeStringSafe(tooLarge)
	assert.ErrorIs(t, err, ErrStringTooLarge)
	assert.Nil(t, decoded)
}

// TestDecodeStringSafe_AtMaxSize tests that input exactly at MAX_DECODE_SIZE is accepted.
func TestDecodeStringSafe_AtMaxSize(t *testing.T) {
	// Create valid base64 at exactly MAX_DECODE_SIZE (must be multiple of 4)
	atMax := strings.Repeat("AAAA", MAX_DECODE_SIZE/4)
	require.Equal(t, MAX_DECODE_SIZE, len(atMax))

	decoded, err := DecodeStringSafe(atMax)
	assert.NoError(t, err)
	assert.NotNil(t, decoded)
}

// TestDecodeStringSafe_RoundTrip verifies encode→decodeSafe round-trip.
func TestDecodeStringSafe_RoundTrip(t *testing.T) {
	original := []byte("round trip test with I2P base64")
	encoded := EncodeToString(original)
	decoded, err := DecodeStringSafe(encoded)
	require.NoError(t, err)
	assert.Equal(t, original, decoded)
}

// TestDecodeStringSafe_InvalidBase64 tests that invalid base64 content returns an error.
func TestDecodeStringSafe_InvalidBase64(t *testing.T) {
	_, err := DecodeStringSafe("!!!!")
	assert.Error(t, err, "should error on invalid base64 characters")
}

// --- Finding: [TEST] Fuzz test for DecodeString (base64_test.go:1) ---

// FuzzDecodeString fuzz tests DecodeString to catch panics on adversarial input.
func FuzzDecodeString(f *testing.F) {
	// Seed corpus with valid and edge-case inputs
	f.Add("SGVsbG8=")
	f.Add("~~~~")
	f.Add("-~~-")
	f.Add("")
	f.Add("A")
	f.Add("====")
	f.Add("SGVsbG8+") // standard base64 char (invalid for I2P)
	f.Add(strings.Repeat("A", 1000))

	f.Fuzz(func(t *testing.T, s string) {
		// DecodeString must never panic regardless of input
		result, err := DecodeString(s)
		if err == nil && len(s) > 0 {
			// If decode succeeds, verify re-encoding produces the same string
			// (canonical form may differ due to padding, so re-decode to verify data)
			reEncoded := EncodeToString(result)
			reDecoded, err2 := DecodeString(reEncoded)
			if err2 != nil {
				t.Fatalf("re-encoding of valid decode result failed: %v", err2)
			}
			if len(result) != len(reDecoded) {
				t.Fatalf("round-trip data length mismatch: %d vs %d", len(result), len(reDecoded))
			}
		}
	})
}

// FuzzDecodeStringSafe fuzz tests DecodeStringSafe to catch panics on adversarial input.
func FuzzDecodeStringSafe(f *testing.F) {
	f.Add("SGVsbG8=")
	f.Add("")
	f.Add("~~~~")
	f.Add(strings.Repeat("A", 1000))

	f.Fuzz(func(t *testing.T, s string) {
		// Must never panic
		_, _ = DecodeStringSafe(s)
	})
}

// --- Finding: [QUALITY] Structural consistency - I2PEncoding location ---

// TestI2PEncodingNotNil verifies the I2PEncoding instance (now in constants.go) is initialized.
func TestI2PEncodingNotNil(t *testing.T) {
	assert.NotNil(t, I2PEncoding, "I2PEncoding must be initialized")
}

// TestMaxDecodeSizeConsistency verifies MAX_DECODE_SIZE is correctly derived from MAX_ENCODE_SIZE.
func TestMaxDecodeSizeConsistency(t *testing.T) {
	expected := ((MAX_ENCODE_SIZE + 2) / 3) * 4
	assert.Equal(t, expected, MAX_DECODE_SIZE,
		"MAX_DECODE_SIZE should be the base64 string length for MAX_ENCODE_SIZE bytes")
}
