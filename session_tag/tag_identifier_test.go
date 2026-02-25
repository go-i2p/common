package session_tag

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewRandomSessionTag(t *testing.T) {
	t.Run("returns non-zero tag", func(t *testing.T) {
		tag, err := NewRandomSessionTag()
		require.NoError(t, err)
		assert.False(t, tag.IsZero(), "random tag should not be zero")
		assert.Equal(t, SessionTagSize, len(tag.Bytes()))
	})

	t.Run("two calls produce different tags", func(t *testing.T) {
		tag1, err := NewRandomSessionTag()
		require.NoError(t, err)
		tag2, err := NewRandomSessionTag()
		require.NoError(t, err)
		assert.False(t, tag1.Equal(tag2), "two random tags should differ")
	})

	t.Run("round-trips through ReadSessionTag", func(t *testing.T) {
		tag, err := NewRandomSessionTag()
		require.NoError(t, err)
		parsed, remainder, err := ReadSessionTag(tag.Bytes())
		require.NoError(t, err)
		assert.Empty(t, remainder)
		assert.True(t, tag.Equal(parsed))
	})
}

func TestNewRandomECIESSessionTag(t *testing.T) {
	t.Run("returns non-zero tag", func(t *testing.T) {
		tag, err := NewRandomECIESSessionTag()
		require.NoError(t, err)
		assert.False(t, tag.IsZero(), "random ECIES tag should not be zero")
		assert.Equal(t, ECIESSessionTagSize, len(tag.Bytes()))
	})

	t.Run("two calls produce different tags", func(t *testing.T) {
		tag1, err := NewRandomECIESSessionTag()
		require.NoError(t, err)
		tag2, err := NewRandomECIESSessionTag()
		require.NoError(t, err)
		assert.False(t, tag1.Equal(tag2), "two random ECIES tags should differ")
	})

	t.Run("round-trips through ReadECIESSessionTag", func(t *testing.T) {
		tag, err := NewRandomECIESSessionTag()
		require.NoError(t, err)
		parsed, remainder, err := ReadECIESSessionTag(tag.Bytes())
		require.NoError(t, err)
		assert.Empty(t, remainder)
		assert.True(t, tag.Equal(parsed))
	})
}

func TestTagIdentifier_SessionTag(t *testing.T) {
	tag, err := NewRandomSessionTag()
	require.NoError(t, err)

	var iface TagIdentifier = tag
	assert.Equal(t, SessionTagSize, len(iface.Bytes()))
	assert.NotEmpty(t, iface.String())
	assert.False(t, iface.IsZero())
}

func TestTagIdentifier_ECIESSessionTag(t *testing.T) {
	tag, err := NewRandomECIESSessionTag()
	require.NoError(t, err)

	var iface TagIdentifier = tag
	assert.Equal(t, ECIESSessionTagSize, len(iface.Bytes()))
	assert.NotEmpty(t, iface.String())
	assert.False(t, iface.IsZero())
}

func TestTagIdentifier_Polymorphism(t *testing.T) {
	st, err := NewRandomSessionTag()
	require.NoError(t, err)
	ecies, err := NewRandomECIESSessionTag()
	require.NoError(t, err)

	// Both types can be held in the same slice.
	tags := []TagIdentifier{st, ecies}
	for _, tag := range tags {
		assert.NotEmpty(t, tag.String())
		assert.False(t, tag.IsZero())
		assert.NotEmpty(t, tag.Bytes())
	}
}

func TestTagIdentifier_EqualBytes_SessionTag(t *testing.T) {
	tag, err := NewRandomSessionTag()
	require.NoError(t, err)

	var iface TagIdentifier = tag

	t.Run("matches own bytes", func(t *testing.T) {
		assert.True(t, iface.EqualBytes(tag.Bytes()))
	})

	t.Run("differs from wrong length", func(t *testing.T) {
		assert.False(t, iface.EqualBytes(tag.Bytes()[:8]))
	})

	t.Run("differs from zero bytes", func(t *testing.T) {
		assert.False(t, iface.EqualBytes(make([]byte, SessionTagSize)))
	})
}

func TestTagIdentifier_EqualBytes_ECIESSessionTag(t *testing.T) {
	tag, err := NewRandomECIESSessionTag()
	require.NoError(t, err)

	var iface TagIdentifier = tag

	t.Run("matches own bytes", func(t *testing.T) {
		assert.True(t, iface.EqualBytes(tag.Bytes()))
	})

	t.Run("differs from wrong length", func(t *testing.T) {
		assert.False(t, iface.EqualBytes(tag.Bytes()[:4]))
	})

	t.Run("differs from zero bytes", func(t *testing.T) {
		assert.False(t, iface.EqualBytes(make([]byte, ECIESSessionTagSize)))
	})
}

func TestTagIdentifier_EqualBytes_Polymorphic(t *testing.T) {
	st, err := NewRandomSessionTag()
	require.NoError(t, err)
	ecies, err := NewRandomECIESSessionTag()
	require.NoError(t, err)

	tags := []TagIdentifier{st, ecies}
	for _, tag := range tags {
		// Every tag must match its own bytes through the interface.
		assert.True(t, tag.EqualBytes(tag.Bytes()), "tag should equal its own bytes")
		// An empty slice must not match any tag.
		assert.False(t, tag.EqualBytes(nil), "tag should not equal nil")
	}
}
