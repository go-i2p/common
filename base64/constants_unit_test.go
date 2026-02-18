package base64

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Unit tests for constants.go

func TestI2PAlphabetLength(t *testing.T) {
	assert.Equal(t, 64, len(I2PEncodeAlphabet),
		"I2P base64 alphabet must be exactly 64 characters")
}

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

func TestI2PAlphabetSubstitutions(t *testing.T) {
	assert.Equal(t, byte('-'), I2PEncodeAlphabet[62],
		"position 62 must be '-' (I2P substitute for '+')")
	assert.Equal(t, byte('~'), I2PEncodeAlphabet[63],
		"position 63 must be '~' (I2P substitute for '/')")
}

func TestI2PAlphabetStandardPrefix(t *testing.T) {
	expected := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	assert.Equal(t, expected, I2PEncodeAlphabet[:62],
		"positions 0-61 must be the standard base64 A-Za-z0-9 characters")
}

func TestI2PAlphabetDoesNotContainStandardChars(t *testing.T) {
	assert.NotContains(t, I2PEncodeAlphabet, "+",
		"I2P alphabet must not contain '+'")
	assert.NotContains(t, I2PEncodeAlphabet, "/",
		"I2P alphabet must not contain '/'")
}

func TestI2PEncodingNotNil(t *testing.T) {
	assert.NotNil(t, I2PEncoding, "I2PEncoding must be initialized")
}

func TestMaxEncodeSizeConstant(t *testing.T) {
	assert.Equal(t, 10*1024*1024, MAX_ENCODE_SIZE, "MAX_ENCODE_SIZE should be 10MB")
}

func TestMaxDecodeSizeConsistency(t *testing.T) {
	expected := ((MAX_ENCODE_SIZE + 2) / 3) * 4
	assert.Equal(t, expected, MAX_DECODE_SIZE,
		"MAX_DECODE_SIZE should be the base64 string length for MAX_ENCODE_SIZE bytes")
}
