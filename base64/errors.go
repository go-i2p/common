// Package base64 error definitions
package base64

import "errors"

var (
	// ErrEmptyData is returned when attempting to encode empty data.
	// Empty data cannot be meaningfully encoded and likely indicates a programming error.
	ErrEmptyData = errors.New("cannot encode empty data")

	// ErrDataTooLarge is returned when data exceeds MAX_ENCODE_SIZE.
	// This prevents excessive memory allocation and potential DoS attacks.
	ErrDataTooLarge = errors.New("data exceeds maximum encodable size")

	// ErrEmptyString is returned when attempting to decode an empty string.
	// Empty strings cannot be meaningfully decoded and likely indicate a programming error.
	ErrEmptyString = errors.New("cannot decode empty string")

	// ErrStringTooLarge is returned when a string exceeds MAX_DECODE_SIZE.
	// This prevents excessive memory allocation and potential DoS attacks during decoding.
	ErrStringTooLarge = errors.New("string exceeds maximum decodable size")
)
