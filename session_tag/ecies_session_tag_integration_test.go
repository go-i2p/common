package session_tag

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestReadECIESSessionTag_WireFrame verifies that ReadECIESSessionTag correctly
// extracts an 8-byte ECIES session tag from the front of a larger protocol-
// framed byte stream, as it would appear in ECIES-X25519-AEAD-Ratchet messages.
func TestReadECIESSessionTag_WireFrame(t *testing.T) {
	payload := []byte("ratchet message body")
	frame := make([]byte, ECIESSessionTagSize+len(payload))
	tagBytes := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	copy(frame[:ECIESSessionTagSize], tagBytes)
	copy(frame[ECIESSessionTagSize:], payload)

	tag, remainder, err := ReadECIESSessionTag(frame)
	require.NoError(t, err)
	assert.True(t, bytes.Equal(tag.Bytes(), tagBytes), "tag bytes must match wire data")
	assert.True(t, bytes.Equal(remainder, payload), "remainder must be the unparsed payload")
}

// TestReadECIESSessionTag_ChainedParsing verifies that multiple 8-byte ECIES
// session tags can be recovered from a contiguous buffer in sequence.
func TestReadECIESSessionTag_ChainedParsing(t *testing.T) {
	const tagCount = 3
	raw := make([]byte, ECIESSessionTagSize*tagCount)
	for i := range raw {
		raw[i] = byte(i + 10)
	}

	buf := raw
	parsed := make([]ECIESSessionTag, 0, tagCount)
	for i := 0; i < tagCount; i++ {
		tag, rem, err := ReadECIESSessionTag(buf)
		require.NoError(t, err, "tag %d: unexpected parse error", i)
		parsed = append(parsed, tag)
		buf = rem
	}

	assert.Empty(t, buf, "all bytes should be consumed after parsing all tags")
	for i, tag := range parsed {
		expected := raw[i*ECIESSessionTagSize : (i+1)*ECIESSessionTagSize]
		assert.True(t, bytes.Equal(tag.Bytes(), expected), "tag %d bytes mismatch", i)
	}
}

// TestECIESSessionTag_EqualBytes_Interface verifies that the EqualBytes method
// operates correctly through the TagIdentifier interface for ECIES tags.
func TestECIESSessionTag_EqualBytes_Interface(t *testing.T) {
	raw := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE}
	tag, err := NewECIESSessionTagFromBytes(raw)
	require.NoError(t, err)

	var iface TagIdentifier = tag
	assert.True(t, iface.EqualBytes(raw), "EqualBytes must match source bytes through interface")
	assert.False(t, iface.EqualBytes(make([]byte, ECIESSessionTagSize)), "EqualBytes must reject zero bytes")
	assert.False(t, iface.EqualBytes(raw[:4]), "EqualBytes must reject wrong-length slice")
}

// TestECIESSessionTag_RoundTrip_Integration exercises the full ECIES tag encode/decode
// cycle: random generation → Bytes() → NewECIESSessionTagFromBytes → equal.
func TestECIESSessionTag_RoundTrip_Integration(t *testing.T) {
	original, err := NewRandomECIESSessionTag()
	require.NoError(t, err)

	decoded, err := NewECIESSessionTagFromBytes(original.Bytes())
	require.NoError(t, err)

	assert.True(t, original.Equal(decoded), "round-tripped tag must equal original")
	assert.True(t, original.EqualBytes(decoded.Bytes()), "EqualBytes round-trip must pass")
}
