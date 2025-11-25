package base32

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEncodeDecodeNotMangled(t *testing.T) {
	assert := assert.New(t)

	// Random pangram
	testInput := []byte("How vexingly quick daft zebras jump!")

	encodedString := EncodeToString(testInput)
	decodedString, err := DecodeString(encodedString)
	assert.Nil(err)

	assert.ElementsMatch(testInput, decodedString)
}

// TestEncodeToStringSafe_ValidInput tests that valid input is encoded correctly
func TestEncodeToStringSafe_ValidInput(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
	}{
		{
			name:  "small input",
			input: []byte("Hello, World!"),
		},
		{
			name:  "pangram",
			input: []byte("How vexingly quick daft zebras jump!"),
		},
		{
			name:  "binary data",
			input: []byte{0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD},
		},
		{
			name:  "single byte",
			input: []byte{0x42},
		},
		{
			name:  "large input (1KB)",
			input: bytes.Repeat([]byte("a"), 1024),
		},
		{
			name:  "large input (100KB)",
			input: bytes.Repeat([]byte("test"), 25*1024),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Encode with safe function
			encoded, err := EncodeToStringSafe(tt.input)
			require.NoError(t, err, "EncodeToStringSafe should not error on valid input")
			require.NotEmpty(t, encoded, "encoded string should not be empty")

			// Verify it matches unsafe version
			expectedEncoded := EncodeToString(tt.input)
			assert.Equal(t, expectedEncoded, encoded, "safe and unsafe versions should produce same output")

			// Verify round-trip
			decoded, err := DecodeString(encoded)
			require.NoError(t, err, "DecodeString should not error")
			assert.Equal(t, tt.input, decoded, "round-trip should preserve data")
		})
	}
}

// TestEncodeToStringSafe_EmptyInput tests that empty input returns an error
func TestEncodeToStringSafe_EmptyInput(t *testing.T) {
	encoded, err := EncodeToStringSafe([]byte{})
	assert.Error(t, err, "should error on empty input")
	assert.Equal(t, ErrEmptyData, err, "should return ErrEmptyData")
	assert.Empty(t, encoded, "encoded string should be empty on error")
}

// TestEncodeToStringSafe_NilInput tests that nil input returns an error
func TestEncodeToStringSafe_NilInput(t *testing.T) {
	encoded, err := EncodeToStringSafe(nil)
	assert.Error(t, err, "should error on nil input")
	assert.Equal(t, ErrEmptyData, err, "should return ErrEmptyData")
	assert.Empty(t, encoded, "encoded string should be empty on error")
}

// TestEncodeToStringSafe_TooLarge tests that oversized input returns an error
func TestEncodeToStringSafe_TooLarge(t *testing.T) {
	// Create data larger than MAX_ENCODE_SIZE
	tooLarge := make([]byte, MAX_ENCODE_SIZE+1)
	encoded, err := EncodeToStringSafe(tooLarge)
	assert.Error(t, err, "should error on oversized input")
	assert.Equal(t, ErrDataTooLarge, err, "should return ErrDataTooLarge")
	assert.Empty(t, encoded, "encoded string should be empty on error")
}

// TestEncodeToStringSafe_MaxSize tests that MAX_ENCODE_SIZE exactly is accepted
func TestEncodeToStringSafe_MaxSize(t *testing.T) {
	// Create data exactly at MAX_ENCODE_SIZE
	maxSize := make([]byte, MAX_ENCODE_SIZE)
	for i := range maxSize {
		maxSize[i] = byte(i % 256)
	}

	encoded, err := EncodeToStringSafe(maxSize)
	assert.NoError(t, err, "should not error at exact max size")
	assert.NotEmpty(t, encoded, "should produce encoded string")

	// Verify it matches unsafe version
	expectedEncoded := EncodeToString(maxSize)
	assert.Equal(t, expectedEncoded, encoded, "should match unsafe version")
}

// TestEncodeToStringSafe_JustUnderMaxSize tests input just under the limit
func TestEncodeToStringSafe_JustUnderMaxSize(t *testing.T) {
	// Create data just under MAX_ENCODE_SIZE
	justUnder := make([]byte, MAX_ENCODE_SIZE-1)
	for i := range justUnder {
		justUnder[i] = byte(i % 256)
	}

	encoded, err := EncodeToStringSafe(justUnder)
	assert.NoError(t, err, "should not error just under max size")
	assert.NotEmpty(t, encoded, "should produce encoded string")
}

// TestMaxEncodeSizeConstant verifies the MAX_ENCODE_SIZE constant is reasonable
func TestMaxEncodeSizeConstant(t *testing.T) {
	assert.Equal(t, 10*1024*1024, MAX_ENCODE_SIZE, "MAX_ENCODE_SIZE should be 10MB")
}

// BenchmarkEncodeToString benchmarks the unsafe encoding function
func BenchmarkEncodeToString(b *testing.B) {
	data := bytes.Repeat([]byte("test"), 256) // 1KB
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = EncodeToString(data)
	}
}

// BenchmarkEncodeToStringSafe benchmarks the safe encoding function
func BenchmarkEncodeToStringSafe(b *testing.B) {
	data := bytes.Repeat([]byte("test"), 256) // 1KB
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = EncodeToStringSafe(data)
	}
}

// BenchmarkEncodeToStringSafe_Large benchmarks safe encoding with larger data
func BenchmarkEncodeToStringSafe_Large(b *testing.B) {
	data := bytes.Repeat([]byte("test"), 256*1024) // 1MB
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = EncodeToStringSafe(data)
	}
}
