package base32

import (
	"testing"
	"unicode"

	"github.com/stretchr/testify/assert"
)

// Tests for constants.go — alphabet correctness and constant values

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

func TestMaxEncodeSizeConstant(t *testing.T) {
	assert.Equal(t, 10*1024*1024, MAX_ENCODE_SIZE, "MAX_ENCODE_SIZE should be 10MB")
}
