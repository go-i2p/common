// Package base32 error definitions
package base32

import "errors"

var (
	// ErrEmptyData is returned when attempting to encode empty data.
	// Empty data cannot be meaningfully encoded and likely indicates a programming error.
	ErrEmptyData = errors.New("cannot encode empty data")

	// ErrDataTooLarge is returned when data exceeds MAX_ENCODE_SIZE.
	// This prevents excessive memory allocation and potential DoS attacks.
	ErrDataTooLarge = errors.New("data exceeds maximum encodable size")

	// ErrInputTooLarge is returned when a base32 string to decode exceeds MAX_DECODE_SIZE.
	// This prevents excessive memory allocation when decoding untrusted input.
	ErrInputTooLarge = errors.New("base32 input string exceeds maximum decodable size")

	// ErrInvalidSuffix is returned when a hostname does not end with ".b32.i2p".
	ErrInvalidSuffix = errors.New("hostname must end with .b32.i2p")

	// ErrNotExtended is returned when attempting to decode a standard-length
	// base32 address (52 chars) as an extended address.
	ErrNotExtended = errors.New("address is standard length, not an extended address")

	// ErrAddressTooShort is returned when decoded address data is too short
	// to contain the required extended address header fields.
	ErrAddressTooShort = errors.New("decoded address data too short for extended format")

	// ErrEmptyPublicKey is returned when an extended address has no public key bytes.
	ErrEmptyPublicKey = errors.New("public key must not be empty")

	// ErrInvalidFlags is returned when reserved flag bits (3–7) are non-zero.
	ErrInvalidFlags = errors.New("reserved flag bits must be zero")

	// ErrKeyTooShort is returned when the public key is too short to produce
	// an extended address distinguishable from a standard 52-char address.
	// Extended addresses require >32 bytes of encoded data (>52 base32 chars).
	ErrKeyTooShort = errors.New("public key too short for a valid extended address")
)
