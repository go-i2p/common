package data

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestHashIntegration tests integration with existing HashData and HashReader functions.
func TestHashIntegration(t *testing.T) {
	t.Run("HashData integration", func(t *testing.T) {
		data := []byte("integration test data")
		h := HashData(data)

		assert.False(t, h.IsZero())
		assert.Len(t, h.Bytes(), 32)

		h2 := HashData(data)
		assert.True(t, h.Equal(h2))
	})

	t.Run("NewHashFromSlice with HashData", func(t *testing.T) {
		original := []byte("test data")
		h1 := HashData(original)

		h1Bytes := h1.Bytes()
		h2, err := NewHashFromSlice(h1Bytes[:])
		require.NoError(t, err)
		assert.True(t, h1.Equal(h2))
	})

	t.Run("HashReader integration", func(t *testing.T) {
		data := []byte("reader test data")
		reader := strings.NewReader(string(data))

		h, err := HashReader(reader)
		require.NoError(t, err)
		assert.False(t, h.IsZero())

		h2 := HashData(data)
		assert.True(t, h.Equal(h2))
	})
}
