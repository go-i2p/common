package data

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestI2PStringRoundTrip(t *testing.T) {
	t.Run("simple string", func(t *testing.T) {
		original := "test string"
		str, err := NewI2PString(original)
		require.NoError(t, err)
		data, err := str.DataSafe()
		require.NoError(t, err)
		assert.Equal(t, original, data)
	})

	t.Run("empty string", func(t *testing.T) {
		original := ""
		str, err := NewI2PString(original)
		require.NoError(t, err)
		data, err := str.DataSafe()
		require.NoError(t, err)
		assert.Equal(t, original, data)
	})

	t.Run("max length string", func(t *testing.T) {
		original := strings.Repeat("x", STRING_MAX_SIZE)
		str, err := NewI2PString(original)
		require.NoError(t, err)
		data, err := str.DataSafe()
		require.NoError(t, err)
		assert.Equal(t, original, data)
	})

	t.Run("bytes round-trip", func(t *testing.T) {
		originalBytes := []byte{0x03, 'a', 'b', 'c'}
		str, err := NewI2PStringFromBytes(originalBytes)
		require.NoError(t, err)
		assert.Equal(t, originalBytes, []byte(str))
	})
}

func TestI2PStringBackwardCompatibility(t *testing.T) {
	t.Run("ToI2PString still works", func(t *testing.T) {
		str, err := ToI2PString("test")
		require.NoError(t, err)
		assert.True(t, str.IsValid())
		data, err := str.DataSafe()
		require.NoError(t, err)
		assert.Equal(t, "test", data)
	})

	t.Run("NewI2PString produces same result as ToI2PString", func(t *testing.T) {
		testStr := "comparison test"
		old, err1 := ToI2PString(testStr)
		newStr, err2 := NewI2PString(testStr)
		require.NoError(t, err1)
		require.NoError(t, err2)
		assert.Equal(t, old, newStr)
	})
}
