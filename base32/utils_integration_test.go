package base32

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Integration tests for utils.go — interoperability, production code paths

func TestPaddedEncodeStripRepadDecodeRoundTrip(t *testing.T) {
	hash := sha256Sum([]byte("production code path test"))

	padded := EncodeToString(hash[:])
	stripped := strings.TrimRight(padded, "=")
	assert.Equal(t, 52, len(stripped),
		"stripped address should be 52 characters")

	paddingNeeded := (8 - len(stripped)%8) % 8
	repadded := stripped + strings.Repeat("=", paddingNeeded)

	decoded, err := DecodeString(repadded)
	require.NoError(t, err, "re-padded string should decode successfully")
	assert.Equal(t, hash[:], decoded, "round-trip should preserve original hash")

	decodedNoPad, err := DecodeStringNoPadding(stripped)
	require.NoError(t, err, "NoPadding decoder should handle stripped string directly")
	assert.Equal(t, hash[:], decodedNoPad,
		"NoPadding decoder should produce same result as re-pad approach")
}

func TestInteroperabilityVector(t *testing.T) {
	hashHex := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	hashBytes, err := hex.DecodeString(hashHex)
	require.NoError(t, err)

	expectedNoPadding := "4oymiquy7qobjgx36tejs35zeqt24qpemsnzgtfeswmrw6csxbkq"
	expectedPadded := "4oymiquy7qobjgx36tejs35zeqt24qpemsnzgtfeswmrw6csxbkq===="

	t.Run("padded encoding matches vector", func(t *testing.T) {
		encoded := EncodeToString(hashBytes)
		assert.Equal(t, expectedPadded, encoded)
	})

	t.Run("unpadded encoding matches vector", func(t *testing.T) {
		encoded := EncodeToStringNoPadding(hashBytes)
		assert.Equal(t, expectedNoPadding, encoded)
	})

	t.Run("padded decode matches vector", func(t *testing.T) {
		decoded, err := DecodeString(expectedPadded)
		require.NoError(t, err)
		assert.Equal(t, hashBytes, decoded)
	})

	t.Run("unpadded decode matches vector", func(t *testing.T) {
		decoded, err := DecodeStringNoPadding(expectedNoPadding)
		require.NoError(t, err)
		assert.Equal(t, hashBytes, decoded)
	})
}
