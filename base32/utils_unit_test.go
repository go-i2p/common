package base32

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Unit tests for utils.go — basic encode/decode, round-trip, safe variants, benchmarks

func TestEncodeDecodeNotMangled(t *testing.T) {
	assert := assert.New(t)

	testInput := []byte("How vexingly quick daft zebras jump!")

	encodedString := EncodeToString(testInput)
	decodedString, err := DecodeString(encodedString)
	assert.Nil(err)

	assert.ElementsMatch(testInput, decodedString)
}

func TestEncodeToStringSafe_ValidInput(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
	}{
		{"small input", []byte("Hello, World!")},
		{"pangram", []byte("How vexingly quick daft zebras jump!")},
		{"binary data", []byte{0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD}},
		{"single byte", []byte{0x42}},
		{"large input (1KB)", bytes.Repeat([]byte("a"), 1024)},
		{"large input (100KB)", bytes.Repeat([]byte("test"), 25*1024)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded, err := EncodeToStringSafe(tt.input)
			require.NoError(t, err, "EncodeToStringSafe should not error on valid input")
			require.NotEmpty(t, encoded, "encoded string should not be empty")

			expectedEncoded := EncodeToString(tt.input)
			assert.Equal(t, expectedEncoded, encoded, "safe and unsafe versions should produce same output")

			decoded, err := DecodeString(encoded)
			require.NoError(t, err, "DecodeString should not error")
			assert.Equal(t, tt.input, decoded, "round-trip should preserve data")
		})
	}
}

func TestDecodeStringSafe_ValidInput(t *testing.T) {
	original := []byte("Hello, I2P network!")
	encoded := EncodeToString(original)

	decoded, err := DecodeStringSafe(encoded)
	require.NoError(t, err)
	assert.Equal(t, original, decoded)
}

func TestDecodeStringSafe_AtMaxSize(t *testing.T) {
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
	hash := sha256Sum([]byte("test safe no-padding"))
	encoded := EncodeToStringNoPadding(hash[:])

	decoded, err := DecodeStringSafeNoPadding(encoded)
	require.NoError(t, err)
	assert.Equal(t, hash[:], decoded)
}

func TestDecodeStringNoPadding_52CharAddress(t *testing.T) {
	hash := sha256Sum([]byte("test destination data"))
	encoded := EncodeToStringNoPadding(hash[:])

	assert.Equal(t, 52, len(encoded),
		"32-byte hash should encode to exactly 52 unpadded base32 characters")

	decoded, err := DecodeStringNoPadding(encoded)
	require.NoError(t, err, "DecodeStringNoPadding should decode 52-char unpadded address")
	assert.Equal(t, hash[:], decoded, "round-trip should preserve original hash bytes")
}

func TestDecodeString_FailsOnUnpadded(t *testing.T) {
	hash := sha256Sum([]byte("test"))
	padded := EncodeToString(hash[:])
	unpadded := trimRight(padded, "=")

	_, err := DecodeString(unpadded)
	assert.Error(t, err, "padded DecodeString should reject unpadded input")

	decoded, err := DecodeStringNoPadding(unpadded)
	require.NoError(t, err, "DecodeStringNoPadding should accept unpadded input")
	assert.Equal(t, hash[:], decoded)
}

// Benchmarks

func BenchmarkEncodeToString(b *testing.B) {
	data := bytes.Repeat([]byte("test"), 256)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = EncodeToString(data)
	}
}

func BenchmarkEncodeToStringSafe(b *testing.B) {
	data := bytes.Repeat([]byte("test"), 256)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = EncodeToStringSafe(data)
	}
}

func BenchmarkEncodeToStringSafe_Large(b *testing.B) {
	data := bytes.Repeat([]byte("test"), 256*1024)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = EncodeToStringSafe(data)
	}
}
