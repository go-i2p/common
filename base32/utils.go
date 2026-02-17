// Package base32 implements utilities for encoding and decoding text using I2P's alphabet
package base32

// EncodeToString encodes binary data to a base32 string using I2P's encoding alphabet.
// It converts arbitrary byte data into a human-readable base32 string representation
// using the I2P-specific lowercase alphabet defined in RFC 3548.
// Example: EncodeToString([]byte{72, 101, 108, 108, 111}) returns "jbswy3dp"
func EncodeToString(data []byte) string {
	// Use I2P-specific base32 encoding with lowercase alphabet
	// This ensures compatibility with I2P destination addresses and identifiers
	return I2PEncoding.EncodeToString(data)
}

// DecodeString decodes a base32 string back to binary data using I2P's encoding alphabet.
// It converts I2P-compatible base32 strings back to their original byte representation.
// Returns an error if the input contains invalid base32 characters or padding.
// Example: DecodeString("jbswy3dp") returns []byte{72, 101, 108, 108, 111}, nil
func DecodeString(data string) ([]byte, error) {
	// Parse I2P-specific base32 string with error handling
	// Validates input characters against I2P alphabet before decoding
	return I2PEncoding.DecodeString(data)
}

// EncodeToStringNoPadding encodes binary data to an unpadded base32 string using I2P's encoding alphabet.
// This is the standard format for I2P .b32.i2p addresses: a 32-byte SHA-256 hash
// encodes to exactly 52 characters with no trailing '=' padding.
func EncodeToStringNoPadding(data []byte) string {
	return I2PEncodingNoPadding.EncodeToString(data)
}

// DecodeStringNoPadding decodes an unpadded base32 string back to binary data.
// This accepts the standard I2P .b32.i2p address format (52 unpadded characters
// for a 32-byte hash).
func DecodeStringNoPadding(data string) ([]byte, error) {
	return I2PEncodingNoPadding.DecodeString(data)
}

// EncodeToStringSafe encodes binary data to a base32 string with input validation.
// Unlike EncodeToString, this function validates the input data size to prevent
// excessive memory allocation and potential DoS attacks. Use this function when
// encoding untrusted or user-provided data.
// Returns an error if data is empty or exceeds MAX_ENCODE_SIZE.
// Example: EncodeToStringSafe([]byte{72, 101, 108, 108, 111}) returns "jbswy3dp", nil
func EncodeToStringSafe(data []byte) (string, error) {
	if len(data) == 0 {
		return "", ErrEmptyData
	}
	if len(data) > MAX_ENCODE_SIZE {
		return "", ErrDataTooLarge
	}
	return I2PEncoding.EncodeToString(data), nil
}
