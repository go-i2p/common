package base32

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Integration tests for extended.go — format verification, interop vectors, production paths

func TestExtendedAddress_Ed25519Standard_56Chars(t *testing.T) {
	// The standard case from the I2P spec: 1-byte sigtypes (Ed25519 pubkey type 7,
	// RedDSA blinded type 11) with a 32-byte key. This produces 35 bytes of data
	// which base32-encodes to exactly 56 characters (35 * 8 / 5 = 56).
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

	// Strip suffix and verify character count
	b32Part := hostname[:len(hostname)-len(B32Suffix)]
	assert.Equal(t, 56, len(b32Part),
		"Ed25519 + RedDSA + 32-byte key should produce 56-char address")

	// Verify hostname ends with .b32.i2p
	assert.True(t, strings.HasSuffix(hostname, B32Suffix))
}

func TestExtendedAddress_TwoBytesSigTypes_60Chars(t *testing.T) {
	// 2-byte sigtypes: 1 flag + 2 pubkey_st + 2 blinded_st + 32 key = 37 bytes
	// 37 bytes → 60 base32 chars (37*8=296, 296/5=59.2, ceil to 60)
	key := make([]byte, 32)
	addr := &ExtendedAddress{
		PubKeySigType:  256,
		BlindedSigType: 512,
		PublicKey:      key,
	}

	hostname, err := EncodeExtendedAddress(addr)
	require.NoError(t, err)

	b32Part := hostname[:len(hostname)-len(B32Suffix)]
	assert.Equal(t, 60, len(b32Part),
		"2-byte sigtypes + 32-byte key should produce 60-char address")
}

func TestExtendedAddress_AllBase32CharsValid(t *testing.T) {
	// Verify all output characters are in the I2P base32 alphabet [a-z2-7]
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i * 7)
	}

	addr := &ExtendedAddress{
		PubKeySigType:  7,
		BlindedSigType: 11,
		PublicKey:      key,
		SecretRequired: true,
	}

	hostname, err := EncodeExtendedAddress(addr)
	require.NoError(t, err)

	b32Part := hostname[:len(hostname)-len(B32Suffix)]
	for i, c := range b32Part {
		isLowerAlpha := c >= 'a' && c <= 'z'
		isValidDigit := c >= '2' && c <= '7'
		assert.True(t, isLowerAlpha || isValidDigit,
			"char at position %d (%c) must be in [a-z2-7]", i, c)
	}
}

func TestExtendedAddress_DistinguishFromStandard(t *testing.T) {
	// Per spec: "Distinguish old from new flavors by length.
	// Old b32 addresses are always {52 chars}.b32.i2p.
	// New ones are {56+ chars}.b32.i2p"
	key := make([]byte, 32)
	addr := &ExtendedAddress{
		PubKeySigType:  7,
		BlindedSigType: 11,
		PublicKey:      key,
	}

	hostname, err := EncodeExtendedAddress(addr)
	require.NoError(t, err)

	b32Part := hostname[:len(hostname)-len(B32Suffix)]
	assert.Greater(t, len(b32Part), StandardB32Chars,
		"extended address must be longer than standard 52-char address")
	assert.True(t, IsExtendedAddress(hostname))

	// Standard address should NOT be identified as extended
	standardAddr := strings.Repeat("a", StandardB32Chars) + B32Suffix
	assert.False(t, IsExtendedAddress(standardAddr))
}

func TestExtendedAddress_ChecksumIntegrity(t *testing.T) {
	// Verify that modifying any byte in the encoded address causes decode failure
	// or produces different results (the XOR checksum provides error detection).
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

	b32Part := hostname[:len(hostname)-len(B32Suffix)]

	// Flip the first character and try decoding
	corrupted := corruptChar(b32Part, 0) + B32Suffix
	decoded, err := DecodeExtendedAddress(corrupted)
	// Either error (invalid flags) or different data
	if err == nil {
		// If it doesn't error, the decoded key should differ
		assert.NotEqual(t, key, decoded.PublicKey,
			"corrupted address should decode to different data")
	}
}

func TestExtendedAddress_DeterministicEncoding(t *testing.T) {
	// Same input must always produce the same output
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	addr := &ExtendedAddress{
		PubKeySigType:  7,
		BlindedSigType: 11,
		PublicKey:      key,
	}

	hostname1, err := EncodeExtendedAddress(addr)
	require.NoError(t, err)

	hostname2, err := EncodeExtendedAddress(addr)
	require.NoError(t, err)

	assert.Equal(t, hostname1, hostname2,
		"encoding must be deterministic")
}

func TestExtendedAddress_DecodedKeyIsIndependentCopy(t *testing.T) {
	// Verify the decoded public key is an independent copy
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

	decoded, err := DecodeExtendedAddress(hostname)
	require.NoError(t, err)

	// Modify the decoded key — original should be unaffected
	decoded.PublicKey[0] = 0xFF
	assert.NotEqual(t, decoded.PublicKey[0], key[0],
		"decoded key should be an independent copy")
}

func TestExtendedAddress_AllFlagCombinations(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	combos := []struct {
		name    string
		secret  bool
		perAuth bool
	}{
		{"no flags", false, false},
		{"secret only", true, false},
		{"per-client only", false, true},
		{"both flags", true, true},
	}

	for _, tt := range combos {
		t.Run(tt.name, func(t *testing.T) {
			addr := &ExtendedAddress{
				PubKeySigType:  7,
				BlindedSigType: 11,
				PublicKey:      key,
				SecretRequired: tt.secret,
				PerClientAuth:  tt.perAuth,
			}

			hostname, err := EncodeExtendedAddress(addr)
			require.NoError(t, err)

			decoded, err := DecodeExtendedAddress(hostname)
			require.NoError(t, err)

			assert.Equal(t, tt.secret, decoded.SecretRequired)
			assert.Equal(t, tt.perAuth, decoded.PerClientAuth)
		})
	}
}

// corruptChar flips a base32 character at the given position to a different
// valid base32 character, ensuring the string remains decodable.
func corruptChar(b32 string, pos int) string {
	chars := []byte(b32)
	if chars[pos] == 'a' {
		chars[pos] = 'b'
	} else {
		chars[pos] = 'a'
	}
	return string(chars)
}
