// Package base32 implements utilities for encoding and decoding text using I2P's alphabet
package base32

import (
	b32 "encoding/base32"
)

// I2PEncodeAlphabet defines the base32 character set used throughout the I2P network.
// This alphabet follows RFC 3548 specifications but uses lowercase letters for consistency
// with I2P addressing conventions and .b32.i2p domain format requirements.
// The alphabet excludes confusing characters like 0, 1, 8, and 9 to prevent user errors.
const I2PEncodeAlphabet = "abcdefghijklmnopqrstuvwxyz234567"

// I2PEncoding provides the standard base32 encoder/decoder used across I2P components.
// This encoding instance is configured with the I2P-specific alphabet and is used for
// generating destination addresses, router identifiers, and other base32-encoded data
// within the I2P ecosystem. It ensures consistent encoding/decoding behavior.
var I2PEncoding *b32.Encoding = b32.NewEncoding(I2PEncodeAlphabet)

// I2PEncodingNoPadding provides a base32 encoder/decoder without padding characters.
// I2P base32 addresses (.b32.i2p) use unpadded base32 encoding: a 32-byte SHA-256 hash
// encodes to exactly 52 characters with no trailing '=' padding.
// Use this encoding for I2P address compatibility.
var I2PEncodingNoPadding *b32.Encoding = b32.NewEncoding(I2PEncodeAlphabet).WithPadding(b32.NoPadding)

// MAX_ENCODE_SIZE defines the maximum number of bytes that can be base32 encoded in a single operation.
// This limit prevents excessive memory allocation and ensures reasonable processing times.
// The limit of 10MB is sufficient for all I2P protocol needs including router infos,
// destinations, and lease sets, while preventing potential DoS through memory exhaustion.
const MAX_ENCODE_SIZE = 10 * 1024 * 1024 // 10 MB
