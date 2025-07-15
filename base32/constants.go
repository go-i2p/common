// Package base32 implements utilities for encoding and decoding text using I2P's alphabet
package base32

import (
	b32 "encoding/base32"
)

// ADDED: I2PEncodeAlphabet defines the base32 character set used throughout the I2P network.
// This alphabet follows RFC 3548 specifications but uses lowercase letters for consistency
// with I2P addressing conventions and .b32.i2p domain format requirements.
// The alphabet excludes confusing characters like 0, 1, 8, and 9 to prevent user errors.
const I2PEncodeAlphabet = "abcdefghijklmnopqrstuvwxyz234567"

// ADDED: I2PEncoding provides the standard base32 encoder/decoder used across I2P components.
// This encoding instance is configured with the I2P-specific alphabet and is used for
// generating destination addresses, router identifiers, and other base32-encoded data
// within the I2P ecosystem. It ensures consistent encoding/decoding behavior.
var I2PEncoding *b32.Encoding = b32.NewEncoding(I2PEncodeAlphabet)
