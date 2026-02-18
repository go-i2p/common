package base64

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
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

func TestDecodeStringSafe_EmptyString(t *testing.T) {
	decoded, err := DecodeStringSafe("")
	assert.ErrorIs(t, err, ErrEmptyString)
	assert.Nil(t, decoded)
}

func TestDecodeStringSafe_TooLarge(t *testing.T) {
	tooLarge := strings.Repeat("A", MAX_DECODE_SIZE+1)
	decoded, err := DecodeStringSafe(tooLarge)
	assert.ErrorIs(t, err, ErrStringTooLarge)
	assert.Nil(t, decoded)
}

func TestDecodeStringSafe_AtMaxSize(t *testing.T) {
	atMax := strings.Repeat("AAAA", MAX_DECODE_SIZE/4)
	decoded, err := DecodeStringSafe(atMax)
	assert.NoError(t, err)
	assert.NotNil(t, decoded)
}

func TestDecodeStringSafe_InvalidBase64(t *testing.T) {
	_, err := DecodeStringSafe("!!!!")
	assert.Error(t, err, "should error on invalid base64 characters")
}

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

func TestDecodeStringMalformedInput(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		expectErr bool
	}{
		{"single padding where none expected", "SGVS=", true},
		{"triple padding", "SGV===", true},
		{"five paddings", "S=====", true},
		{"single char", "A", true},
		{"two chars no padding", "SG", true},
		{"three chars no padding", "SGV", true},
		{"embedded space", "SGVs bG8=", true},
		{"embedded newline (stripped by Go)", "SGVs\nbG8=", false},
		{"embedded tab", "SGVs\tbG8=", true},
		{"leading space", " SGVsbG8=", true},
		{"trailing space", "SGVsbG8= ", true},
		{"empty string (valid per Go stdlib)", "", false},
		{"only padding", "====", true},
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
