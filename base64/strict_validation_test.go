package base64

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Validation tests for strict decoding and unpadded decode behavior

// TestDecodeStringStrict_RejectsNewlines verifies that DecodeStringStrict rejects
// embedded \r and \n characters, matching the Java I2P reference implementation behavior.
func TestDecodeStringStrict_RejectsNewlines(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"embedded newline", "SGVs\nbG8="},
		{"embedded carriage return", "SGVs\rbG8="},
		{"embedded CRLF", "SGVs\r\nbG8="},
		{"leading newline", "\nSGVsbG8="},
		{"trailing newline", "SGVsbG8=\n"},
		{"multiple newlines", "SG\nVs\nbG8="},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DecodeStringStrict(tt.input)
			assert.ErrorIs(t, err, ErrContainsNewline,
				"DecodeStringStrict should reject input with embedded newlines")
		})
	}
}

// TestDecodeStringStrict_AcceptsValid verifies that valid base64 without newlines
// is decoded correctly.
func TestDecodeStringStrict_AcceptsValid(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []byte
	}{
		{"simple hello", "SGVsbG8=", []byte("Hello")},
		{"I2P chars tilde", "~~~~", []byte{0xff, 0xff, 0xff}},
		{"I2P chars dash and tilde", "-~~-", []byte{0xfb, 0xff, 0xfe}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decoded, err := DecodeStringStrict(tt.input)
			require.NoError(t, err)
			assert.Equal(t, tt.want, decoded)
		})
	}
}

// TestDecodeStringStrict_RejectsInvalidBase64 verifies that invalid base64 is
// still rejected even without newlines.
func TestDecodeStringStrict_RejectsInvalidBase64(t *testing.T) {
	_, err := DecodeStringStrict("!!!!")
	assert.Error(t, err)
	assert.NotErrorIs(t, err, ErrContainsNewline,
		"should fail with base64 error, not newline error")
}

// TestDecodeString_AcceptsEmbeddedNewline documents that the non-strict DecodeString
// silently strips embedded newlines (Go encoding/base64 behavior).
// This is a known behavioral divergence from the Java I2P reference implementation.
func TestDecodeString_AcceptsEmbeddedNewline(t *testing.T) {
	decoded, err := DecodeString("SGVs\nbG8=")
	require.NoError(t, err, "Go's base64 decoder strips newlines")
	assert.Equal(t, []byte("Hello"), decoded)
}

// TestDecodeString_UnpaddedBehavior documents the behavior when decoding unpadded
// base64 with the padded decoder. The standard decoder returns partial data and an error.
// Use DecodeStringNoPadding for unpadded input instead.
func TestDecodeString_UnpaddedBehavior(t *testing.T) {
	// "SGVsbG8" is "Hello" without the trailing '=' padding
	decoded, err := DecodeString("SGVsbG8")
	assert.Error(t, err, "padded decoder should error on unpadded input")
	// Go returns partial data (first complete 3-byte block) alongside the error
	assert.True(t, len(decoded) < len([]byte("Hello")),
		"should return partial data, not full decode")
}

// TestDecodeStringNoPadding_DecodesUnpadded verifies that the NoPadding variant
// correctly decodes the same input that the padded decoder rejects.
func TestDecodeStringNoPadding_DecodesUnpadded(t *testing.T) {
	decoded, err := DecodeStringNoPadding("SGVsbG8")
	require.NoError(t, err, "NoPadding decoder should accept unpadded input")
	assert.Equal(t, []byte("Hello"), decoded)
}
