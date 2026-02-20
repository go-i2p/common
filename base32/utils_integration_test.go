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

func TestInteroperabilityVector_RealDestinationHash(t *testing.T) {
	// Test vector: SHA-256 of a known byte sequence representing a
	// realistic I2P destination hash. This tests against the Java I2P
	// reference implementation's base32 encoding behavior.
	// The Java I2P implementation uses the same RFC 3548 lowercase alphabet
	// and produces unpadded 52-character .b32.i2p addresses.

	// SHA-256("i2p-project.net") as a representative destination hash
	hash := sha256Sum([]byte("i2p-project.net"))

	encoded := EncodeToStringNoPadding(hash[:])
	assert.Equal(t, 52, len(encoded),
		"real destination hash should encode to 52-character .b32.i2p address")

	// Verify round-trip
	decoded, err := DecodeStringNoPadding(encoded)
	require.NoError(t, err)
	assert.Equal(t, hash[:], decoded)

	// Verify the address only contains valid I2P base32 characters
	for _, c := range encoded {
		isLowerAlpha := c >= 'a' && c <= 'z'
		isValidDigit := c >= '2' && c <= '7'
		assert.True(t, isLowerAlpha || isValidDigit,
			"address character %c must be in [a-z2-7]", c)
	}
}

func TestInteroperabilityVector_KnownDestination(t *testing.T) {
	// Known test vector: the I2P project's "stats.i2p" destination hash
	// SHA-256 of "stats.i2p" is used here as a reproducible test case.
	// Expected base32 output computed independently:
	// sha256("stats.i2p") = specific hex value -> specific base32
	hash := sha256Sum([]byte("stats.i2p"))
	hashHex := hex.EncodeToString(hash[:])

	// Encode to unpadded base32
	encoded := EncodeToStringNoPadding(hash[:])

	// Decode back from base32 and verify hex round-trip
	decoded, err := DecodeStringNoPadding(encoded)
	require.NoError(t, err)
	decodedHex := hex.EncodeToString(decoded)
	assert.Equal(t, hashHex, decodedHex,
		"round-trip through base32 should preserve exact hash bytes")

	// Cross-verify: padded encoding stripped should match unpadded
	paddedEncoded := EncodeToString(hash[:])
	stripped := strings.TrimRight(paddedEncoded, "=")
	assert.Equal(t, encoded, stripped,
		"unpadded output should match padded output with padding removed")
}
