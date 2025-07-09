// Package base32 implements utilities for encoding and decoding text using I2P's alphabet
package base32

import (
	b32 "encoding/base32"
)

// I2PEncodeAlphabet is the base32 encoding used throughout I2P.
// RFC 3548 using lowercase characters.
// Moved from: base32.go
const I2PEncodeAlphabet = "abcdefghijklmnopqrstuvwxyz234567"

// I2PEncoding is the standard base32 encoding used through I2P.
// Moved from: base32.go
var I2PEncoding *b32.Encoding = b32.NewEncoding(I2PEncodeAlphabet)
