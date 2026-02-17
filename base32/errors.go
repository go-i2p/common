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
)
