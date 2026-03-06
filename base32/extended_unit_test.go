package base32

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Unit tests for extended.go — basic encode/decode, round-trip, helpers

func TestEncodeDecodeRoundTrip_OneByteSigTypes(t *testing.T) {
	// Standard case: Ed25519 (sigtype 7) + RedDSA (sigtype 11), 32-byte key
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	original := &ExtendedAddress{
		PubKeySigType:  7,
		BlindedSigType: 11,
		PublicKey:      key,
	}

	hostname, err := EncodeExtendedAddress(original)
	require.NoError(t, err)

	decoded, err := DecodeExtendedAddress(hostname)
	require.NoError(t, err)

	assert.Equal(t, original.PubKeySigType, decoded.PubKeySigType)
	assert.Equal(t, original.BlindedSigType, decoded.BlindedSigType)
	assert.Equal(t, original.PublicKey, decoded.PublicKey)
	assert.Equal(t, original.SecretRequired, decoded.SecretRequired)
	assert.Equal(t, original.PerClientAuth, decoded.PerClientAuth)
}

func TestEncodeDecodeRoundTrip_TwoByteSigTypes(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 0x80)
	}

	original := &ExtendedAddress{
		PubKeySigType:  0x0100, // Requires 2-byte sigtype
		BlindedSigType: 0x0200,
		PublicKey:      key,
	}

	hostname, err := EncodeExtendedAddress(original)
	require.NoError(t, err)

	decoded, err := DecodeExtendedAddress(hostname)
	require.NoError(t, err)

	assert.Equal(t, original.PubKeySigType, decoded.PubKeySigType)
	assert.Equal(t, original.BlindedSigType, decoded.BlindedSigType)
	assert.Equal(t, original.PublicKey, decoded.PublicKey)
}

func TestEncodeDecodeRoundTrip_WithSecretAndAuth(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i * 3)
	}

	original := &ExtendedAddress{
		PubKeySigType:  7,
		BlindedSigType: 11,
		PublicKey:      key,
		SecretRequired: true,
		PerClientAuth:  true,
	}

	hostname, err := EncodeExtendedAddress(original)
	require.NoError(t, err)

	decoded, err := DecodeExtendedAddress(hostname)
	require.NoError(t, err)

	assert.Equal(t, original.PubKeySigType, decoded.PubKeySigType)
	assert.Equal(t, original.BlindedSigType, decoded.BlindedSigType)
	assert.Equal(t, original.PublicKey, decoded.PublicKey)
	assert.True(t, decoded.SecretRequired)
	assert.True(t, decoded.PerClientAuth)
}

func TestEncodeDecodeRoundTrip_SecretOnly(t *testing.T) {
	key := make([]byte, 32)
	original := &ExtendedAddress{
		PubKeySigType:  7,
		BlindedSigType: 11,
		PublicKey:      key,
		SecretRequired: true,
		PerClientAuth:  false,
	}

	hostname, err := EncodeExtendedAddress(original)
	require.NoError(t, err)

	decoded, err := DecodeExtendedAddress(hostname)
	require.NoError(t, err)

	assert.True(t, decoded.SecretRequired)
	assert.False(t, decoded.PerClientAuth)
}

func TestEncodeDecodeRoundTrip_PerClientAuthOnly(t *testing.T) {
	key := make([]byte, 32)
	original := &ExtendedAddress{
		PubKeySigType:  7,
		BlindedSigType: 11,
		PublicKey:      key,
		SecretRequired: false,
		PerClientAuth:  true,
	}

	hostname, err := EncodeExtendedAddress(original)
	require.NoError(t, err)

	decoded, err := DecodeExtendedAddress(hostname)
	require.NoError(t, err)

	assert.False(t, decoded.SecretRequired)
	assert.True(t, decoded.PerClientAuth)
}

func TestEncodeDecodeRoundTrip_MinimalViableKey(t *testing.T) {
	// Minimum viable key: for 1-byte sigtypes (3-byte header), the key must
	// be at least 30 bytes so total data > 32 bytes → >52 base32 chars.
	key := make([]byte, 30)
	for i := range key {
		key[i] = byte(i + 0x10)
	}

	original := &ExtendedAddress{
		PubKeySigType:  7,
		BlindedSigType: 11,
		PublicKey:      key,
	}

	hostname, err := EncodeExtendedAddress(original)
	require.NoError(t, err)

	decoded, err := DecodeExtendedAddress(hostname)
	require.NoError(t, err)

	assert.Equal(t, original.PubKeySigType, decoded.PubKeySigType)
	assert.Equal(t, original.BlindedSigType, decoded.BlindedSigType)
	assert.Equal(t, original.PublicKey, decoded.PublicKey)
}

func TestIsExtendedAddress(t *testing.T) {
	tests := []struct {
		name     string
		hostname string
		expected bool
	}{
		{
			name:     "standard 52-char address",
			hostname: "4oymiquy7qobjgx36tejs35zeqt24qpemsnzgtfeswmrw6csxbkq.b32.i2p",
			expected: false,
		},
		{
			name:     "no suffix",
			hostname: "4oymiquy7qobjgx36tejs35zeqt24qpemsnzgtfeswmrw6csxbkq",
			expected: false,
		},
		{
			name:     "empty string",
			hostname: "",
			expected: false,
		},
		{
			name:     "only suffix",
			hostname: ".b32.i2p",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, IsExtendedAddress(tt.hostname))
		})
	}

	// Test with a real extended address
	key := make([]byte, 32)
	addr := &ExtendedAddress{
		PubKeySigType:  7,
		BlindedSigType: 11,
		PublicKey:      key,
	}
	hostname, err := EncodeExtendedAddress(addr)
	require.NoError(t, err)
	assert.True(t, IsExtendedAddress(hostname),
		"encoded extended address should be recognized")
}

func TestExtendedAddressHostnameSuffix(t *testing.T) {
	key := make([]byte, 32)
	addr := &ExtendedAddress{
		PubKeySigType:  7,
		BlindedSigType: 11,
		PublicKey:      key,
	}

	hostname, err := EncodeExtendedAddress(addr)
	require.NoError(t, err)
	assert.True(t, len(hostname) > len(B32Suffix))
	assert.Equal(t, B32Suffix, hostname[len(hostname)-len(B32Suffix):])
}

func TestDecodeExtendedAddress_CaseInsensitive(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	addr := &ExtendedAddress{
		PubKeySigType:  7,
		BlindedSigType: 11,
		PublicKey:      key,
	}

	hostname, err := EncodeExtendedAddress(addr)
	require.NoError(t, err)

	// Uppercase should decode identically
	upper := ""
	for _, c := range hostname {
		if c >= 'a' && c <= 'z' {
			upper += string(rune(c - 32))
		} else {
			upper += string(c)
		}
	}

	decoded, err := DecodeExtendedAddress(upper)
	require.NoError(t, err)
	assert.Equal(t, key, decoded.PublicKey)
}

func TestBuildFlags(t *testing.T) {
	tests := []struct {
		name     string
		secret   bool
		perCli   bool
		twoByte  bool
		expected byte
	}{
		{"no flags", false, false, false, 0x00},
		{"secret only", true, false, false, FlagSecretRequired},
		{"per-client only", false, true, false, FlagPerClientAuth},
		{"two-byte only", false, false, true, FlagTwoByteSigTypes},
		{
			"all flags", true, true, true,
			FlagTwoByteSigTypes | FlagSecretRequired | FlagPerClientAuth,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected,
				buildFlags(tt.secret, tt.perCli, tt.twoByte))
		})
	}
}

func TestCloneBytes(t *testing.T) {
	original := []byte{1, 2, 3, 4}
	cloned := cloneBytes(original)
	assert.Equal(t, original, cloned)

	// Modify clone, original must not change
	cloned[0] = 99
	assert.NotEqual(t, original[0], cloned[0])
}
