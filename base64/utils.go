// Package base64 utilities for encoding and decoding
package base64

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

// DecodeStringSafe converts I2P-compatible base64 strings back to binary with input validation.
// Unlike DecodeString, this function validates the input string length to prevent
// excessive memory allocation and potential DoS attacks. Use this function when
// decoding untrusted or network-provided data.
// Returns an error if the string is empty or exceeds MAX_DECODE_SIZE.
// Example: DecodeStringSafe("SGVsbG8=") returns []byte{72, 101, 108, 108, 111}, nil
func DecodeStringSafe(str string) ([]byte, error) {
	if len(str) == 0 {
		return nil, ErrEmptyString
	}
	if len(str) > MAX_DECODE_SIZE {
		return nil, ErrStringTooLarge
	}
	return I2PEncoding.DecodeString(str)
}
