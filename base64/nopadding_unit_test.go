package base64

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Unit tests for NoPadding encode/decode variants

func TestEncodeToStringNoPadding_Basic(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		wantLen int // expected encoded length (no trailing '=')
	}{
		{"3 bytes (no padding needed)", []byte("abc"), 4},     // 3 bytes → 4 chars, no padding
		{"5 bytes (would need 1 pad)", []byte("Hello"), 7},    // "SGVsbG8" without '='
		{"1 byte (would need 2 pads)", []byte{0x42}, 2},       // "Qg" without "=="
		{"2 bytes (would need 1 pad)", []byte{0x42, 0x43}, 3}, // "QkM" without "="
		{"6 bytes (no padding needed)", []byte("abcdef"), 8},  // 6 bytes → 8 chars, no padding
		{"binary 0xFF", []byte{0xff, 0xff, 0xff}, 4},          // "~~~~" no padding needed
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded := EncodeToStringNoPadding(tt.input)
			assert.Equal(t, tt.wantLen, len(encoded), "encoded length")
			assert.False(t, strings.Contains(encoded, "="), "should not contain padding")
		})
	}
}

func TestEncodeToStringNoPadding_RoundTrip(t *testing.T) {
	inputs := [][]byte{
		[]byte("Hello"),
		[]byte("A"),
		[]byte("AB"),
		[]byte("ABC"),
		{0xff, 0xff, 0xff},
		{0xfb, 0xff, 0xfe},
		bytes.Repeat([]byte("test data"), 100),
	}

	for _, input := range inputs {
		encoded := EncodeToStringNoPadding(input)
		decoded, err := DecodeStringNoPadding(encoded)
		require.NoError(t, err, "DecodeStringNoPadding should not error for input len=%d", len(input))
		assert.Equal(t, input, decoded, "round-trip should preserve data for input len=%d", len(input))
	}
}

func TestDecodeStringNoPadding_AcceptsUnpadded(t *testing.T) {
	// "Hello" padded is "SGVsbG8=" — unpadded is "SGVsbG8"
	decoded, err := DecodeStringNoPadding("SGVsbG8")
	require.NoError(t, err)
	assert.Equal(t, []byte("Hello"), decoded)
}

func TestDecodeStringNoPadding_RejectsPadded(t *testing.T) {
	// NoPadding encoding should reject padded input
	_, err := DecodeStringNoPadding("SGVsbG8=")
	assert.Error(t, err, "NoPadding decoder should reject padded input")
}

func TestEncodeToStringNoPadding_NilAndEmpty(t *testing.T) {
	assert.Equal(t, "", EncodeToStringNoPadding(nil), "nil should return empty string")
	assert.Equal(t, "", EncodeToStringNoPadding([]byte{}), "empty should return empty string")
}

func TestEncodeToStringNoPadding_MatchesPaddedWithTrim(t *testing.T) {
	// Verify that NoPadding output == TrimRight(padded, "=")
	inputs := [][]byte{
		[]byte("A"),
		[]byte("AB"),
		[]byte("ABC"),
		[]byte("ABCD"),
		[]byte("Hello, World!"),
		{0x00},
		{0xff, 0xfe},
	}

	for _, input := range inputs {
		padded := EncodeToString(input)
		trimmed := strings.TrimRight(padded, "=")
		noPad := EncodeToStringNoPadding(input)
		assert.Equal(t, trimmed, noPad,
			"NoPadding should equal trimmed padded for input %v", input)
	}
}

// Tests for Safe NoPadding variants

func TestEncodeToStringSafeNoPadding_ValidInput(t *testing.T) {
	encoded, err := EncodeToStringSafeNoPadding([]byte("Hello"))
	require.NoError(t, err)
	assert.Equal(t, "SGVsbG8", encoded)
	assert.False(t, strings.Contains(encoded, "="))
}

func TestEncodeToStringSafeNoPadding_EmptyInput(t *testing.T) {
	_, err := EncodeToStringSafeNoPadding([]byte{})
	assert.ErrorIs(t, err, ErrEmptyData)
}

func TestEncodeToStringSafeNoPadding_NilInput(t *testing.T) {
	_, err := EncodeToStringSafeNoPadding(nil)
	assert.ErrorIs(t, err, ErrEmptyData)
}

func TestEncodeToStringSafeNoPadding_TooLarge(t *testing.T) {
	_, err := EncodeToStringSafeNoPadding(make([]byte, MAX_ENCODE_SIZE+1))
	assert.ErrorIs(t, err, ErrDataTooLarge)
}

func TestEncodeToStringSafeNoPadding_AtMaxSize(t *testing.T) {
	data := make([]byte, MAX_ENCODE_SIZE)
	encoded, err := EncodeToStringSafeNoPadding(data)
	require.NoError(t, err)
	assert.NotEmpty(t, encoded)
	assert.False(t, strings.Contains(encoded, "="))
}

func TestDecodeStringSafeNoPadding_ValidInput(t *testing.T) {
	decoded, err := DecodeStringSafeNoPadding("SGVsbG8")
	require.NoError(t, err)
	assert.Equal(t, []byte("Hello"), decoded)
}

func TestDecodeStringSafeNoPadding_EmptyString(t *testing.T) {
	_, err := DecodeStringSafeNoPadding("")
	assert.ErrorIs(t, err, ErrEmptyString)
}

func TestDecodeStringSafeNoPadding_TooLarge(t *testing.T) {
	_, err := DecodeStringSafeNoPadding(strings.Repeat("A", MAX_DECODE_SIZE+1))
	assert.ErrorIs(t, err, ErrStringTooLarge)
}

func TestDecodeStringSafeNoPadding_RoundTrip(t *testing.T) {
	original := []byte("round trip NoPadding test")
	encoded := EncodeToStringNoPadding(original)
	decoded, err := DecodeStringSafeNoPadding(encoded)
	require.NoError(t, err)
	assert.Equal(t, original, decoded)
}

// Benchmarks for NoPadding variants

func BenchmarkEncodeToStringNoPadding(b *testing.B) {
	data := bytes.Repeat([]byte("test"), 256)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = EncodeToStringNoPadding(data)
	}
}

func BenchmarkDecodeStringNoPadding(b *testing.B) {
	data := EncodeToStringNoPadding(bytes.Repeat([]byte("test"), 256))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = DecodeStringNoPadding(data)
	}
}
