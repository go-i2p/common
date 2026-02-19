package data

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestHashEdgeCases tests edge cases and boundary conditions.
func TestHashEdgeCases(t *testing.T) {
	t.Run("all ones hash", func(t *testing.T) {
		var allOnes [32]byte
		for i := 0; i < 32; i++ {
			allOnes[i] = 0xff
		}

		h := NewHash(allOnes)
		assert.False(t, h.IsZero())
		assert.Equal(t, allOnes, h.Bytes())

		str := h.String()
		assert.Equal(t, strings.Repeat("ff", 32), str)
	})

	t.Run("single bit difference", func(t *testing.T) {
		var bytes1 [32]byte
		var bytes2 [32]byte
		bytes2[31] = 1 // Only last bit different

		h1 := NewHash(bytes1)
		h2 := NewHash(bytes2)
		assert.False(t, h1.Equal(h2))
	})

	t.Run("ReadHash with exact boundary", func(t *testing.T) {
		data := make([]byte, 32)
		_, remaining, err := ReadHash(data)
		require.NoError(t, err)
		assert.Empty(t, remaining)
	})

	t.Run("ReadHash with large remaining data", func(t *testing.T) {
		data := make([]byte, 1000)
		for i := 0; i < 1000; i++ {
			data[i] = byte(i % 256)
		}

		_, remaining, err := ReadHash(data)
		require.NoError(t, err)
		assert.Len(t, remaining, 968)
		assert.Equal(t, data[32:], remaining)
	})
}
