// Package base32 implements utilities for encoding and decoding text using I2P's alphabet
package base32

import (
	b32 "encoding/base32"
)

// I2PEncodeAlphabet defines the base32 character set used throughout the I2P network.
// This is the standard RFC 3548/4648 base32 alphabet in lowercase form.
// The lowercase variant is required for I2P .b32.i2p address compatibility.
// The base32 standard inherently uses only a-z and 2-7 (26+6=32 symbols).
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

// MAX_DECODE_SIZE defines the maximum length of a base32 string that can be decoded in a single operation.
// This is the base32-encoded expansion of MAX_ENCODE_SIZE (ceil(10MB * 8/5)).
// For I2P .b32.i2p addresses, the expected input is 52 characters; this limit provides ample headroom
// while preventing memory exhaustion from untrusted input.
const MAX_DECODE_SIZE = (MAX_ENCODE_SIZE*8 + 4) / 5 // ~16 MB of base32 text
