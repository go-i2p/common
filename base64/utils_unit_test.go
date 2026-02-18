package base64

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Unit tests for utils.go — basic encode/decode, round-trip, safe variants, benchmarks

func TestEncodeDecodeNotMangled(t *testing.T) {
	assert := assert.New(t)

	testInput := []byte("Glib jocks quiz nymph to vex dwarf.")

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
		{"pangram", []byte("Glib jocks quiz nymph to vex dwarf.")},
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

func TestDecodeStringSafe_RoundTrip(t *testing.T) {
	original := []byte("round trip test with I2P base64")
	encoded := EncodeToString(original)
	decoded, err := DecodeStringSafe(encoded)
	require.NoError(t, err)
	assert.Equal(t, original, decoded)
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
