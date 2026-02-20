// Package base32 implements utilities for encoding and decoding text using I2P's alphabet
package base32

import (
	"fmt"
	"hash/crc32"
	"strings"
)

// Extended base32 address constants, per the I2P naming spec (0.9.40+).
// See: https://geti2p.net/spec/b32encrypted
const (
	// FlagTwoByteSigTypes indicates that signature types use 2 bytes each
	// instead of the default 1 byte. Per I2P spec notes: "Don't expect
	// 2-byte sigtypes to ever happen, we're only up to 13."
	FlagTwoByteSigTypes byte = 0x01

	// FlagSecretRequired indicates a secret is needed to decrypt the
	// encrypted leaseset.
	FlagSecretRequired byte = 0x02

	// FlagPerClientAuth indicates per-client authentication (client
	// private key) is required.
	FlagPerClientAuth byte = 0x04

	// flagReservedMask covers reserved flag bits (3–7) that must be zero.
	flagReservedMask byte = 0xF8

	// B32Suffix is the standard I2P base32 address suffix.
	B32Suffix = ".b32.i2p"

	// StandardB32Chars is the character count of a standard (non-extended)
	// base32 address: 52 chars encoding a 32-byte SHA-256 hash.
	StandardB32Chars = 52

	// minExtendedDataLen is the minimum decoded byte length for an extended
	// address: 1 flag + 1 pubkey sigtype + 1 blinded sigtype + 1 key byte.
	minExtendedDataLen = 4

	// headerLen1Byte is the header size with 1-byte signature types.
	headerLen1Byte = 3 // flag + pubkeySigType + blindedSigType

	// headerLen2Byte is the header size with 2-byte signature types.
	headerLen2Byte = 5 // flag + 2*pubkeySigType + 2*blindedSigType
)

// ExtendedAddress represents an I2P extended base32 address for encrypted
// leasesets, as defined in the I2P naming specification (0.9.40+).
//
// Extended addresses encode the destination's public key along with signature
// type metadata, enabling clients to fetch and decrypt encrypted leasesets
// without requiring a full destination from an address book.
//
// Standard base32 addresses are 52 characters (32-byte SHA-256 hash).
// Extended addresses are 56+ characters and contain the public key directly.
type ExtendedAddress struct {
	// PubKeySigType is the signature type of the destination's public key.
	// Common value: 7 (EdDSA_SHA512_Ed25519).
	PubKeySigType uint16

	// BlindedSigType is the signature type used for the blinded key.
	// Common value: 11 (RedDSA_SHA512_Ed25519).
	BlindedSigType uint16

	// PublicKey is the raw public key bytes. Length is determined by the
	// signature type (e.g., 32 bytes for Ed25519).
	PublicKey []byte

	// SecretRequired indicates a secret is needed to decrypt the
	// encrypted leaseset.
	SecretRequired bool

	// PerClientAuth indicates per-client authentication (client private
	// key) is required.
	PerClientAuth bool
}

// EncodeExtendedAddress constructs an extended base32 .b32.i2p hostname
// from the given address components, following the I2P naming specification.
//
// Returns the full hostname (e.g., "{56 chars}.b32.i2p") or an error.
func EncodeExtendedAddress(addr *ExtendedAddress) (string, error) {
	if addr == nil {
		return "", ErrEmptyData
	}
	if len(addr.PublicKey) == 0 {
		return "", ErrEmptyPublicKey
	}

	data := marshalExtendedData(addr)
	// Extended addresses must encode to >52 base32 chars (>32 bytes of data)
	// to be distinguishable from standard base32 addresses per the I2P spec.
	if len(data) <= 32 {
		return "", ErrKeyTooShort
	}
	applyChecksum(data)
	return EncodeToStringNoPadding(data) + B32Suffix, nil
}

// DecodeExtendedAddress decodes a .b32.i2p hostname string into its
// constituent extended address components.
//
// Returns ErrNotExtended if the address is standard length (52 chars).
// Returns ErrInvalidSuffix if the hostname does not end with ".b32.i2p".
func DecodeExtendedAddress(hostname string) (*ExtendedAddress, error) {
	b32Part, err := stripSuffix(hostname)
	if err != nil {
		return nil, err
	}
	if len(b32Part) <= StandardB32Chars {
		return nil, ErrNotExtended
	}

	data, err := DecodeStringNoPadding(b32Part)
	if err != nil {
		return nil, fmt.Errorf("base32 decode: %w", err)
	}
	if len(data) < minExtendedDataLen {
		return nil, ErrAddressTooShort
	}
	return unmarshalExtendedData(data)
}

// IsExtendedAddress returns true if the hostname appears to be an extended
// base32 address (more than 52 characters before the .b32.i2p suffix).
func IsExtendedAddress(hostname string) bool {
	b32Part, err := stripSuffix(hostname)
	if err != nil {
		return false
	}
	return len(b32Part) > StandardB32Chars
}

// stripSuffix removes the ".b32.i2p" suffix and returns the base32 portion.
func stripSuffix(hostname string) (string, error) {
	lower := strings.ToLower(hostname)
	if !strings.HasSuffix(lower, B32Suffix) {
		return "", ErrInvalidSuffix
	}
	return lower[:len(lower)-len(B32Suffix)], nil
}

// marshalExtendedData builds the raw binary representation of an extended
// address before checksum application. The layout is:
//
//	[flag][pubkey sigtype (1–2 bytes)][blinded sigtype (1–2 bytes)][public key]
func marshalExtendedData(addr *ExtendedAddress) []byte {
	twoByte := addr.PubKeySigType > 255 || addr.BlindedSigType > 255
	flags := buildFlags(addr.SecretRequired, addr.PerClientAuth, twoByte)

	hdrLen := headerLen1Byte
	if twoByte {
		hdrLen = headerLen2Byte
	}

	data := make([]byte, hdrLen+len(addr.PublicKey))
	data[0] = flags

	if twoByte {
		data[1] = byte(addr.PubKeySigType >> 8)
		data[2] = byte(addr.PubKeySigType)
		data[3] = byte(addr.BlindedSigType >> 8)
		data[4] = byte(addr.BlindedSigType)
	} else {
		data[1] = byte(addr.PubKeySigType)
		data[2] = byte(addr.BlindedSigType)
	}
	copy(data[hdrLen:], addr.PublicKey)
	return data
}

// buildFlags constructs the flag byte from boolean fields.
func buildFlags(secret, perClient, twoByte bool) byte {
	var f byte
	if twoByte {
		f |= FlagTwoByteSigTypes
	}
	if secret {
		f |= FlagSecretRequired
	}
	if perClient {
		f |= FlagPerClientAuth
	}
	return f
}

// unmarshalExtendedData parses raw binary data into an ExtendedAddress,
// reversing the CRC-32 checksum XOR on the first 3 bytes.
func unmarshalExtendedData(data []byte) (*ExtendedAddress, error) {
	checksum := crc32.ChecksumIEEE(data[3:])
	flags := data[0] ^ byte(checksum)
	b1 := data[1] ^ byte(checksum>>8)
	b2 := data[2] ^ byte(checksum>>16)

	if flags&flagReservedMask != 0 {
		return nil, ErrInvalidFlags
	}

	addr := &ExtendedAddress{
		SecretRequired: flags&FlagSecretRequired != 0,
		PerClientAuth:  flags&FlagPerClientAuth != 0,
	}

	if flags&FlagTwoByteSigTypes != 0 {
		return parseTwoByteSigTypes(addr, data, b1, b2)
	}
	addr.PubKeySigType = uint16(b1)
	addr.BlindedSigType = uint16(b2)
	addr.PublicKey = cloneBytes(data[headerLen1Byte:])
	return addr, nil
}

// parseTwoByteSigTypes handles the 2-byte signature type case during decode.
func parseTwoByteSigTypes(
	addr *ExtendedAddress, data []byte, b1, b2 byte,
) (*ExtendedAddress, error) {
	if len(data) < headerLen2Byte+1 {
		return nil, ErrAddressTooShort
	}
	addr.PubKeySigType = uint16(b1)<<8 | uint16(b2)
	addr.BlindedSigType = uint16(data[3])<<8 | uint16(data[4])
	addr.PublicKey = cloneBytes(data[headerLen2Byte:])
	return addr, nil
}

// applyChecksum computes CRC-32 (IEEE) of data[3:] and XORs the checksum
// into the first 3 bytes, per the I2P extended base32 specification.
func applyChecksum(data []byte) {
	checksum := crc32.ChecksumIEEE(data[3:])
	data[0] ^= byte(checksum)
	data[1] ^= byte(checksum >> 8)
	data[2] ^= byte(checksum >> 16)
}

// cloneBytes returns an independent copy of a byte slice.
func cloneBytes(b []byte) []byte {
	c := make([]byte, len(b))
	copy(c, b)
	return c
}
