package base32

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Validation tests for utils.go — invalid input, boundary conditions, error paths

func TestEncodeToStringSafe_EmptyInput(t *testing.T) {
	encoded, err := EncodeToStringSafe([]byte{})
	assert.Error(t, err, "should error on empty input")
	assert.Equal(t, ErrEmptyData, err, "should return ErrEmptyData")
	assert.Empty(t, encoded, "encoded string should be empty on error")
}

func TestEncodeToStringSafe_NilInput(t *testing.T) {
	encoded, err := EncodeToStringSafe(nil)
	assert.Error(t, err, "should error on nil input")
	assert.Equal(t, ErrEmptyData, err, "should return ErrEmptyData")
	assert.Empty(t, encoded, "encoded string should be empty on error")
}

func TestEncodeToStringSafe_TooLarge(t *testing.T) {
	tooLarge := make([]byte, MAX_ENCODE_SIZE+1)
	encoded, err := EncodeToStringSafe(tooLarge)
	assert.Error(t, err, "should error on oversized input")
	assert.Equal(t, ErrDataTooLarge, err, "should return ErrDataTooLarge")
	assert.Empty(t, encoded, "encoded string should be empty on error")
}

func TestEncodeToStringSafe_MaxSize(t *testing.T) {
	maxSize := make([]byte, MAX_ENCODE_SIZE)
	for i := range maxSize {
		maxSize[i] = byte(i % 256)
	}

	encoded, err := EncodeToStringSafe(maxSize)
	assert.NoError(t, err, "should not error at exact max size")
	assert.NotEmpty(t, encoded, "should produce encoded string")

	expectedEncoded := EncodeToString(maxSize)
	assert.Equal(t, expectedEncoded, encoded, "should match unsafe version")
}

func TestEncodeToStringSafe_JustUnderMaxSize(t *testing.T) {
	justUnder := make([]byte, MAX_ENCODE_SIZE-1)
	for i := range justUnder {
		justUnder[i] = byte(i % 256)
	}

	encoded, err := EncodeToStringSafe(justUnder)
	assert.NoError(t, err, "should not error just under max size")
	assert.NotEmpty(t, encoded, "should produce encoded string")
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

func TestDecodeStringSafeNoPadding_EmptyInput(t *testing.T) {
	_, err := DecodeStringSafeNoPadding("")
	assert.ErrorIs(t, err, ErrEmptyData)
}

func TestDecodeStringSafeNoPadding_TooLargeInput(t *testing.T) {
	tooLarge := strings.Repeat("a", MAX_DECODE_SIZE+1)
	_, err := DecodeStringSafeNoPadding(tooLarge)
	assert.ErrorIs(t, err, ErrInputTooLarge)
}

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

func TestSHA256HashRoundTrip(t *testing.T) {
	hash := sha256Sum([]byte("i2p destination for testing"))

	t.Run("padded encoding is 56 chars", func(t *testing.T) {
		encoded := EncodeToString(hash[:])
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
