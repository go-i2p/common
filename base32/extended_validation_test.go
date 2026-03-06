package base32

import (
	"hash/crc32"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Validation tests for extended.go — invalid inputs, error paths, boundary conditions

func TestEncodeExtendedAddress_NilAddress(t *testing.T) {
	_, err := EncodeExtendedAddress(nil)
	assert.ErrorIs(t, err, ErrEmptyData)
}

func TestEncodeExtendedAddress_EmptyPublicKey(t *testing.T) {
	addr := &ExtendedAddress{
		PubKeySigType:  7,
		BlindedSigType: 11,
		PublicKey:      nil,
	}
	_, err := EncodeExtendedAddress(addr)
	assert.ErrorIs(t, err, ErrEmptyPublicKey)

	addr.PublicKey = []byte{}
	_, err = EncodeExtendedAddress(addr)
	assert.ErrorIs(t, err, ErrEmptyPublicKey)
}

func TestEncodeExtendedAddress_KeyTooShort(t *testing.T) {
	// A 1-byte key with 1-byte sigtypes = 4 bytes total ≤ 32,
	// which would produce ≤52 base32 chars (indistinguishable from standard).
	addr := &ExtendedAddress{
		PubKeySigType:  7,
		BlindedSigType: 11,
		PublicKey:      []byte{0x42},
	}
	_, err := EncodeExtendedAddress(addr)
	assert.ErrorIs(t, err, ErrKeyTooShort)

	// 29-byte key with 3-byte header = 32 bytes total, still ≤32
	addr.PublicKey = make([]byte, 29)
	_, err = EncodeExtendedAddress(addr)
	assert.ErrorIs(t, err, ErrKeyTooShort)

	// 30-byte key with 3-byte header = 33 bytes total, >32 → OK
	addr.PublicKey = make([]byte, 30)
	_, err = EncodeExtendedAddress(addr)
	assert.NoError(t, err)
}

func TestDecodeExtendedAddress_InvalidSuffix(t *testing.T) {
	tests := []struct {
		name     string
		hostname string
	}{
		{"no suffix", "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx"},
		{"wrong suffix", "abcdef.onion"},
		{"empty string", ""},
		{"partial suffix", "abcdef.b32"},
		{"only .i2p", "abcdef.i2p"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DecodeExtendedAddress(tt.hostname)
			assert.ErrorIs(t, err, ErrInvalidSuffix)
		})
	}
}

func TestDecodeExtendedAddress_StandardLength(t *testing.T) {
	// A 52-char base32 address is standard, not extended
	addr52 := strings.Repeat("a", StandardB32Chars) + B32Suffix
	_, err := DecodeExtendedAddress(addr52)
	assert.ErrorIs(t, err, ErrNotExtended)
}

func TestDecodeExtendedAddress_ShorterThanStandard(t *testing.T) {
	addr10 := strings.Repeat("a", 10) + B32Suffix
	_, err := DecodeExtendedAddress(addr10)
	assert.ErrorIs(t, err, ErrNotExtended)
}

func TestDecodeExtendedAddress_InvalidBase32Chars(t *testing.T) {
	// 57 characters but with invalid base32 chars (0, 1, 8, 9 not in alphabet)
	invalid := strings.Repeat("a", 53) + "0189" + B32Suffix
	_, err := DecodeExtendedAddress(invalid)
	assert.Error(t, err)
	assert.NotErrorIs(t, err, ErrNotExtended,
		"error should be about decoding, not about length")
}

func TestDecodeExtendedAddress_InvalidFlags_ReservedBitsSet(t *testing.T) {
	// Construct a valid extended address, then corrupt the flags
	key := make([]byte, 32)
	addr := &ExtendedAddress{
		PubKeySigType:  7,
		BlindedSigType: 11,
		PublicKey:      key,
	}

	// Marshal without checksum to tamper with flags
	data := marshalExtendedData(addr)

	// Set a reserved bit (bit 3) before applying checksum
	data[0] |= 0x08
	applyChecksum(data)

	encoded := EncodeToStringNoPadding(data) + B32Suffix
	_, err := DecodeExtendedAddress(encoded)
	assert.ErrorIs(t, err, ErrInvalidFlags)
}

func TestDecodeExtendedAddress_TooShortData(t *testing.T) {
	// Encode data that is only 3 bytes (flag + 2 sigtypes, no key)
	// This should fail because we need at least 4 bytes (flag + 2 sigtypes + 1 key byte)
	data := []byte{0x00, 0x07, 0x0B}
	applyChecksum(data)

	encoded := EncodeToStringNoPadding(data) + B32Suffix
	// 3 bytes = 5 base32 chars, which is < 52, so ErrNotExtended is returned
	_, err := DecodeExtendedAddress(encoded)
	assert.Error(t, err)
}

func TestDecodeExtendedAddress_TwoByteHeaderTooShort(t *testing.T) {
	// Test via unmarshalExtendedData directly since short data that encodes
	// to >52 chars would need to be large, making the test impractical via
	// the public API. Here we test the internal parsing with 5 bytes of data:
	// flag=0x01 (2-byte sigtypes), 2 bytes pubkey, 2 bytes blinded, NO key.

	shortData := []byte{0x01, 0x00, 0x01, 0x00, 0x02}
	// Reverse the checksum XOR that unmarshal expects
	checksum := crc32.ChecksumIEEE(shortData[3:])
	shortData[0] ^= byte(checksum)
	shortData[1] ^= byte(checksum >> 8)
	shortData[2] ^= byte(checksum >> 16)

	_, err := unmarshalExtendedData(shortData)
	assert.ErrorIs(t, err, ErrAddressTooShort)
}

func TestIsExtendedAddress_InvalidInputs(t *testing.T) {
	assert.False(t, IsExtendedAddress(""))
	assert.False(t, IsExtendedAddress(".b32.i2p"))
	assert.False(t, IsExtendedAddress("not-an-address"))
	assert.False(t, IsExtendedAddress("short.b32.i2p"))
}

func TestExtendedAddress_AutoTwoByteSigType(t *testing.T) {
	key := make([]byte, 32)
	// If either sigtype > 255, 2-byte mode should be auto-selected
	addr := &ExtendedAddress{
		PubKeySigType:  256, // Exceeds 1-byte range
		BlindedSigType: 11,
		PublicKey:      key,
	}
	hostname, err := EncodeExtendedAddress(addr)
	assert.NoError(t, err)

	decoded, err := DecodeExtendedAddress(hostname)
	assert.NoError(t, err)
	assert.Equal(t, uint16(256), decoded.PubKeySigType)
	assert.Equal(t, uint16(11), decoded.BlindedSigType)
}

func TestExtendedAddress_AutoTwoByteSigType_BlindedOnly(t *testing.T) {
	key := make([]byte, 32)
	addr := &ExtendedAddress{
		PubKeySigType:  7,
		BlindedSigType: 300, // Exceeds 1-byte range
		PublicKey:      key,
	}
	hostname, err := EncodeExtendedAddress(addr)
	assert.NoError(t, err)

	decoded, err := DecodeExtendedAddress(hostname)
	assert.NoError(t, err)
	assert.Equal(t, uint16(7), decoded.PubKeySigType)
	assert.Equal(t, uint16(300), decoded.BlindedSigType)
}
