// Package base64 utilities for encoding and decoding
package base64

import "strings"

// EncodeToString converts arbitrary binary data to I2P-compatible base64 string representation.
// This function takes raw byte data and produces a human-readable string using I2P's modified
// base64 alphabet. The output is compatible with I2P destination addresses, router identifiers,
// and other network protocol elements that require base64 encoding.
// The encoding process applies standard base64 padding rules with '=' characters as needed.
//
// Note: EncodeToString(nil) and EncodeToString([]byte{}) both return "" without error.
// These two cases are indistinguishable in the output. Use EncodeToStringSafe for
// input validation that rejects nil and empty data.
//
// Example: EncodeToString([]byte{72, 101, 108, 108, 111}) returns "SGVsbG8=" (Hello in I2P base64)
func EncodeToString(data []byte) string {
	return I2PEncoding.EncodeToString(data)
}

// DecodeString converts I2P-compatible base64 strings back to their original binary form.
// This function reverses the encoding process, taking base64 strings that use I2P's alphabet
// and converting them back to the original byte data. It validates input characters against
// the I2P alphabet and handles standard base64 padding requirements.
//
// Note: Go's encoding/base64 silently strips \r and \n characters before decoding. Use
// DecodeStringStrict if you need to reject strings containing embedded newlines, matching
// the Java I2P reference implementation's behavior (since 0.9.14).
//
// Returns an error if the input contains invalid characters or malformed padding.
// Example: DecodeString("SGVsbG8=") returns []byte{72, 101, 108, 108, 111}, nil (Hello decoded)
func DecodeString(str string) ([]byte, error) {
	return I2PEncoding.DecodeString(str)
}

// DecodeStringStrict converts I2P-compatible base64 strings back to binary, rejecting
// embedded newlines (\r, \n). The Java I2P reference implementation (since 0.9.14)
// rejects whitespace in base64 strings. Use this function when strict interoperability
// with the Java implementation is required.
func DecodeStringStrict(str string) ([]byte, error) {
	if strings.ContainsAny(str, "\r\n") {
		return nil, ErrContainsNewline
	}
	return I2PEncoding.DecodeString(str)
}

// EncodeToStringNoPadding encodes binary data to an unpadded I2P base64 string.
// The Java I2P reference implementation (since 0.9.14) accepts base64 without trailing
// '=' padding. This function produces unpadded output for interoperability.
//
// Note: EncodeToStringNoPadding(nil) and EncodeToStringNoPadding([]byte{}) both return ""
// without error. Use EncodeToStringSafeNoPadding for input validation.
func EncodeToStringNoPadding(data []byte) string {
	return I2PEncodingNoPadding.EncodeToString(data)
}

// DecodeStringNoPadding decodes an unpadded I2P base64 string back to binary data.
// This accepts base64 strings without trailing '=' padding, matching the Java I2P
// reference implementation's leniency (since 0.9.14).
func DecodeStringNoPadding(str string) ([]byte, error) {
	return I2PEncodingNoPadding.DecodeString(str)
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

// EncodeToStringSafeNoPadding encodes binary data to an unpadded I2P base64 string with
// input validation. This combines the unpadded encoding of EncodeToStringNoPadding with
// the size validation of EncodeToStringSafe.
// Returns an error if data is empty or exceeds MAX_ENCODE_SIZE.
func EncodeToStringSafeNoPadding(data []byte) (string, error) {
	if len(data) == 0 {
		return "", ErrEmptyData
	}
	if len(data) > MAX_ENCODE_SIZE {
		return "", ErrDataTooLarge
	}
	return I2PEncodingNoPadding.EncodeToString(data), nil
}

// DecodeStringSafeNoPadding decodes an unpadded I2P base64 string with input validation.
// This combines the unpadded decoding of DecodeStringNoPadding with the size validation
// of DecodeStringSafe. Use for decoding untrusted unpadded base64 from I2P peers.
// Returns an error if the string is empty or exceeds MAX_DECODE_SIZE.
func DecodeStringSafeNoPadding(str string) ([]byte, error) {
	if len(str) == 0 {
		return nil, ErrEmptyString
	}
	if len(str) > MAX_DECODE_SIZE {
		return nil, ErrStringTooLarge
	}
	return I2PEncodingNoPadding.DecodeString(str)
}
