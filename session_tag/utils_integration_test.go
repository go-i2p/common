package session_tag

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestReadSessionTag_WireFrame verifies that ReadSessionTag correctly extracts
// a 32-byte session tag from the front of a larger protocol-framed byte stream
// (simulating how session tags appear embedded in I2P wire messages).
func TestReadSessionTag_WireFrame(t *testing.T) {
	// Build a simulated wire frame: [32-byte tag][payload]
	payload := []byte("I2P protocol payload data")
	frame := make([]byte, SessionTagSize+len(payload))
	tagBytes := make([]byte, SessionTagSize)
	for i := range tagBytes {
		tagBytes[i] = byte(i + 1)
	}
	copy(frame[:SessionTagSize], tagBytes)
	copy(frame[SessionTagSize:], payload)

	tag, remainder, err := ReadSessionTag(frame)
	require.NoError(t, err)
	assert.True(t, bytes.Equal(tag.Bytes(), tagBytes), "tag bytes must match wire data")
	assert.True(t, bytes.Equal(remainder, payload), "remainder must be unparsed payload")
}

// TestReadSessionTag_ChainedParsing verifies that multiple session tags can be
// parsed in sequence from a single contiguous buffer, as would occur when
// processing a batch of new-session or existing-session tags.
func TestReadSessionTag_ChainedParsing(t *testing.T) {
	const tagCount = 4
	raw := make([]byte, SessionTagSize*tagCount)
	for i := 0; i < tagCount*SessionTagSize; i++ {
		raw[i] = byte(i)
	}

	buf := raw
	parsed := make([]SessionTag, 0, tagCount)
	for i := 0; i < tagCount; i++ {
		tag, rem, err := ReadSessionTag(buf)
		require.NoError(t, err, "tag %d: unexpected parse error", i)
		parsed = append(parsed, tag)
		buf = rem
	}

	assert.Empty(t, buf, "all bytes should be consumed after parsing all tags")
	for i, tag := range parsed {
		expected := raw[i*SessionTagSize : (i+1)*SessionTagSize]
		assert.True(t, bytes.Equal(tag.Bytes(), expected), "tag %d bytes mismatch", i)
	}
}

// TestNewSessionTag_ReturnedPointerIsDistinct verifies that NewSessionTag
// returns a pointer whose modification does not affect the original data slice,
// confirming the copy-on-parse contract.
func TestNewSessionTag_ReturnedPointerIsDistinct(t *testing.T) {
	data := make([]byte, SessionTagSize+2)
	for i := range data {
		data[i] = 0xAB
	}

	st, remainder, err := NewSessionTag(data)
	require.NoError(t, err)
	require.NotNil(t, st)
	assert.Equal(t, 2, len(remainder))

	// Mutate origin; the already-returned tag must be unaffected.
	copy(data[:SessionTagSize], make([]byte, SessionTagSize))
	expected := make([]byte, SessionTagSize)
	for i := range expected {
		expected[i] = 0xAB
	}
	assert.True(t, bytes.Equal(st.Bytes(), expected), "returned tag must be independent of source slice")
}
