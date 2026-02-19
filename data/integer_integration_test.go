package data

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestNewIntegerFromBytesIntegration tests integration between new methods
func TestNewIntegerFromBytesIntegration(t *testing.T) {
	assert := assert.New(t)

	t.Run("construct and check zero", func(t *testing.T) {
		bytes := []byte{0x00, 0x00}
		integer, err := NewIntegerFromBytes(bytes)
		assert.Nil(err)
		assert.True(integer.IsZero(), "Newly created zero integer should return true for IsZero()")

		value, err := integer.IntSafe()
		assert.Nil(err)
		assert.Equal(0, value, "Zero integer should convert to 0")
	})

	t.Run("construct and convert non-zero", func(t *testing.T) {
		bytes := []byte{0x00, 0x00, 0x01, 0x00}
		integer, err := NewIntegerFromBytes(bytes)
		assert.Nil(err)
		assert.False(integer.IsZero(), "Non-zero integer should return false for IsZero()")

		value, err := integer.IntSafe()
		assert.Nil(err)
		assert.Equal(256, value, "Integer should convert to correct value")
	})

	t.Run("round trip NewIntegerFromInt to IntSafe", func(t *testing.T) {
		testValues := []int{0, 1, 127, 255, 256, 65535}
		for _, original := range testValues {
			integer, err := NewIntegerFromInt(original, 4)
			assert.Nil(err, "NewIntegerFromInt should succeed for value %d", original)

			value, err := integer.IntSafe()
			assert.Nil(err, "IntSafe should succeed for value %d", original)
			assert.Equal(original, value, "Round trip should preserve value %d", original)
		}
	})
}
