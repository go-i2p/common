package data

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestReadIntegerBoundsValidation verifies that ReadInteger validates
// the size parameter (must be 1-8).
func TestReadIntegerBoundsValidation(t *testing.T) {
	data := []byte{0x01, 0x02, 0x03, 0x04}

	t.Run("size zero returns nil", func(t *testing.T) {
		result, remainder := ReadInteger(data, 0)
		assert.Nil(t, result)
		assert.Equal(t, data, remainder, "Original data should be returned as remainder")
	})

	t.Run("negative size returns nil", func(t *testing.T) {
		result, remainder := ReadInteger(data, -1)
		assert.Nil(t, result)
		assert.Equal(t, data, remainder)
	})

	t.Run("size exceeds max returns nil", func(t *testing.T) {
		result, remainder := ReadInteger(data, 9)
		assert.Nil(t, result)
		assert.Equal(t, data, remainder)
	})

	t.Run("valid size 1", func(t *testing.T) {
		result, remainder := ReadInteger(data, 1)
		assert.Equal(t, Integer([]byte{0x01}), result)
		assert.Equal(t, []byte{0x02, 0x03, 0x04}, remainder)
	})

	t.Run("valid size 4", func(t *testing.T) {
		result, remainder := ReadInteger(data, 4)
		assert.Equal(t, Integer(data), result)
		assert.Empty(t, remainder)
	})

	t.Run("max valid size 8", func(t *testing.T) {
		bigData := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09}
		result, remainder := ReadInteger(bigData, 8)
		assert.Equal(t, Integer(bigData[:8]), result)
		assert.Equal(t, []byte{0x09}, remainder)
	})
}

// TestNewIntegerFromIntSizeValidation verifies that NewIntegerFromInt
// returns an error (not a panic) for invalid size values.
func TestNewIntegerFromIntSizeValidation(t *testing.T) {
	t.Run("negative size returns error", func(t *testing.T) {
		result, err := NewIntegerFromInt(1, -1)
		require.Error(t, err, "Negative size should return error, not panic")
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "invalid integer size")
	})

	t.Run("zero size returns error", func(t *testing.T) {
		result, err := NewIntegerFromInt(1, 0)
		require.Error(t, err, "Zero size should return error")
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "invalid integer size")
	})

	t.Run("size exceeds max returns error", func(t *testing.T) {
		result, err := NewIntegerFromInt(1, 9)
		require.Error(t, err, "Size > MAX_INTEGER_SIZE should return error")
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "invalid integer size")
	})

	t.Run("valid size 1", func(t *testing.T) {
		result, err := NewIntegerFromInt(42, 1)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, 42, result.Int())
	})

	t.Run("valid size 8", func(t *testing.T) {
		result, err := NewIntegerFromInt(123456789, 8)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, 123456789, result.Int())
	})

	t.Run("negative value returns error", func(t *testing.T) {
		result, err := NewIntegerFromInt(-1, 2)
		require.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "negative value")
	})
}
