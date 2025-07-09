// Package base32 implements utilities for encoding and decoding text using I2P's alphabet
package base32

// EncodeToString encodes []byte to a base32 string using I2PEncoding
func EncodeToString(data []byte) string {
	return I2PEncoding.EncodeToString(data)
}

// DecodeString decodes base32 string to []byte I2PEncoding
func DecodeString(data string) ([]byte, error) {
	return I2PEncoding.DecodeString(data)
}
