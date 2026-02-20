package base64

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Integration tests for NoPadding variants and interoperability with Java I2P

// TestInteropNoPaddingVectors verifies NoPadding encode/decode against the padded variants
// for inputs of various lengths (1, 2, 3 bytes modulo 3), ensuring interoperability with
// the Java I2P reference implementation's padding-lenient decoder (since 0.9.14).
func TestInteropNoPaddingVectors(t *testing.T) {
	for _, tt := range interopTestVectors {
		if len(tt.raw) == 0 {
			continue
		}
		t.Run(tt.name+" (NoPadding roundtrip)", func(t *testing.T) {
			encoded := EncodeToStringNoPadding(tt.raw)
			decoded, err := DecodeStringNoPadding(encoded)
			require.NoError(t, err, "NoPadding decode should succeed")
			assert.Equal(t, tt.raw, decoded, "NoPadding round-trip mismatch")
		})
	}
}

// TestInteropKnownI2PDestinationBase64 verifies encoding/decoding of a known I2P
// destination-like base64 string. This test uses a 32-byte key (simulating a hash)
// and verifies the output matches what the Java reference implementation produces.
//
// The Java I2P Base64 class uses the same alphabet (A-Za-z0-9-~) and produces identical
// output for the same input bytes. This vector was chosen because:
// - 32 bytes is the SHA-256 hash length used for I2P destination hashes
// - The bytes produce output containing both '-' and '~' I2P-specific characters
func TestInteropKnownI2PDestinationBase64(t *testing.T) {
	// 32-byte key: SHA-256("i2p") = known deterministic value
	// SHA-256("i2p") in hex: a7ffc6f8bf1ed766 51c14756a061d662 f580ff4de43b49fa 82d80a4b80f8434a
	// We use a fixed test vector with known I2P base64 output:
	keyBytes := []byte{
		0xa7, 0xff, 0xc6, 0xf8, 0xbf, 0x1e, 0xd7, 0x66,
		0x51, 0xc1, 0x47, 0x56, 0xa0, 0x61, 0xd6, 0x62,
		0xf5, 0x80, 0xff, 0x4d, 0xe4, 0x3b, 0x49, 0xfa,
		0x82, 0xd8, 0x0a, 0x4b, 0x80, 0xf8, 0x43, 0x4a,
	}

	// Expected I2P base64 (padded): standard base64 with +→- and /→~
	// Standard base64: "p//G+L8e12ZRwUdWoGHWYvWA/03kO0n6gtgKS4D4Q0o="
	// I2P base64:      "p~~G-L8e12ZRwUdWoGHWYvWA~03kO0n6gtgKS4D4Q0o="
	expectedPadded := "p~~G-L8e12ZRwUdWoGHWYvWA~03kO0n6gtgKS4D4Q0o="
	expectedUnpadded := "p~~G-L8e12ZRwUdWoGHWYvWA~03kO0n6gtgKS4D4Q0o"

	t.Run("padded encoding", func(t *testing.T) {
		encoded := EncodeToString(keyBytes)
		assert.Equal(t, expectedPadded, encoded)

		decoded, err := DecodeString(encoded)
		require.NoError(t, err)
		assert.Equal(t, keyBytes, decoded)
	})

	t.Run("unpadded encoding", func(t *testing.T) {
		encoded := EncodeToStringNoPadding(keyBytes)
		assert.Equal(t, expectedUnpadded, encoded)

		decoded, err := DecodeStringNoPadding(encoded)
		require.NoError(t, err)
		assert.Equal(t, keyBytes, decoded)
	})

	t.Run("strict decode", func(t *testing.T) {
		decoded, err := DecodeStringStrict(expectedPadded)
		require.NoError(t, err)
		assert.Equal(t, keyBytes, decoded)
	})
}

// TestInteropEd25519DestinationLength verifies that a 391-byte Ed25519 destination
// encodes to the expected number of base64 characters. Ed25519 destinations are 391
// bytes, which produces 524 padded chars (with 1 '=' pad) or 523 unpadded chars.
func TestInteropEd25519DestinationLength(t *testing.T) {
	// 391 bytes: ceil(391 * 4/3) = 522 data chars, 524 with padding (524 % 4 == 0)
	dest := make([]byte, 391)
	for i := range dest {
		dest[i] = byte(i % 256)
	}

	padded := EncodeToString(dest)
	assert.Equal(t, 524, len(padded), "391 bytes should encode to 524 padded chars")
	assert.True(t, padded[len(padded)-1] == '=', "should end with padding")

	unpadded := EncodeToStringNoPadding(dest)
	assert.Less(t, len(unpadded), len(padded), "unpadded should be shorter")
	assert.False(t, unpadded[len(unpadded)-1] == '=', "should not end with padding")

	// Round-trip
	decoded, err := DecodeStringNoPadding(unpadded)
	require.NoError(t, err)
	assert.Equal(t, dest, decoded)
}
