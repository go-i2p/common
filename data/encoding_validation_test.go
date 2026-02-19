package data

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDecodeIntNExceedsIntRange(t *testing.T) {
	t.Run("max uint64 exceeds int range", func(t *testing.T) {
		data := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
		_, err := DecodeIntN(data)
		require.Error(t, err, "Should error when value exceeds max int")
		assert.Contains(t, err.Error(), "exceeds maximum int")
	})

	t.Run("value at int boundary", func(t *testing.T) {
		data := []byte{0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
		_, err := DecodeIntN(data)
		require.Error(t, err, "2^63 should exceed max int")
	})

	t.Run("value just below int boundary", func(t *testing.T) {
		data := []byte{0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
		result, err := DecodeIntN(data)
		require.NoError(t, err, "max int64 should decode successfully")
		assert.Equal(t, int(^uint(0)>>1), result)
	})
}
