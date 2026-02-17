// Package base64 utilities and encoding instances
package base64

import (
	b64 "encoding/base64"
)

// I2PEncoding provides the standard base64 encoder/decoder instance for all I2P components.
// This encoding instance is pre-configured with the I2P-specific alphabet and optimizes performance
// by reusing the same encoder across multiple operations. It handles the complex character mapping
// required for I2P network compatibility while maintaining standard base64 semantics.
// The instance is thread-safe and can be used concurrently across goroutines.
// Example: Used internally by EncodeToString and DecodeString for consistent encoding behavior.
var I2PEncoding *b64.Encoding = b64.NewEncoding(I2PEncodeAlphabet)

// EncodeToString converts arbitrary binary data to I2P-compatible base64 string representation.
// This function takes raw byte data and produces a human-readable string using I2P's modified
// base64 alphabet. The output is compatible with I2P destination addresses, router identifiers,
// and other network protocol elements that require base64 encoding.
// The encoding process applies standard base64 padding rules with '=' characters as needed.
// Example: EncodeToString([]byte{72, 101, 108, 108, 111}) returns "SGVsbG8=" (Hello in I2P base64)
func EncodeToString(data []byte) string {
	// Use I2P-specific encoding instance for consistent network compatibility
	// Applies character substitutions (- for +, ~ for /) required by I2P protocols
	return I2PEncoding.EncodeToString(data)
}

// DecodeString converts I2P-compatible base64 strings back to their original binary form.
// This function reverses the encoding process, taking base64 strings that use I2P's alphabet
// and converting them back to the original byte data. It validates input characters against
// the I2P alphabet and handles standard base64 padding requirements.
// Returns an error if the input contains invalid characters or malformed padding.
// Example: DecodeString("SGVsbG8=") returns []byte{72, 101, 108, 108, 111}, nil (Hello decoded)
func DecodeString(str string) ([]byte, error) {
	// Parse I2P base64 string with comprehensive error handling
	// Validates character set conformity and padding structure before decoding
	return I2PEncoding.DecodeString(str)
}

// EncodeToStringSafe encodes binary data to a base64 string with input validation.
// Unlike EncodeToString, this function validates the input data size to prevent
// excessive memory allocation and potential DoS attacks. Use this function when
// encoding untrusted or user-provided data.
// Returns an error if data is empty or exceeds MAX_ENCODE_SIZE.
// Example: EncodeToStringSafe([]byte{72, 101, 108, 108, 111}) returns "SGVsbG8=", nil
func EncodeToStringSafe(data []byte) (string, error) {
	if len(data) == 0 {
		return "", ErrEmptyData
	}
	if len(data) > MAX_ENCODE_SIZE {
		return "", ErrDataTooLarge
	}
	return I2PEncoding.EncodeToString(data), nil
}
