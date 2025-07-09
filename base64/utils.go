// Package base64 utilities and encoding instances
package base64

import (
	b64 "encoding/base64"
)

// I2PEncoding is the standard base64 encoding used through I2P.
var I2PEncoding *b64.Encoding = b64.NewEncoding(I2PEncodeAlphabet)

// EncodeToString encodes data to string using I2P base64 encoding.
func EncodeToString(data []byte) string {
	return I2PEncoding.EncodeToString(data)
}

// DecodeString decodes base64 string to []byte using I2P encoding.
func DecodeString(str string) ([]byte, error) {
	return I2PEncoding.DecodeString(str)
}
