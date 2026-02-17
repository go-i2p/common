// Package base64 constants
package base64

import (
	b64 "encoding/base64"
)

// I2PEncodeAlphabet defines the I2P-specific base64 character set used throughout the network.
// This alphabet follows RFC 4648 standard base64 encoding with two critical modifications:
// - "/" is replaced with "~" to avoid filesystem path conflicts
// - "+" is replaced with "-" to ensure URL-safe encoding without percent-encoding
// The alphabet maintains the standard ordering: A-Z (0-25), a-z (26-51), 0-9 (52-61), - (62), ~ (63).
// This encoding is essential for I2P destination addresses, router identifiers, and network data structures.
// Example usage: Used in .b64.i2p addresses and binary data serialization across I2P protocols.
const I2PEncodeAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-~"

// MAX_ENCODE_SIZE defines the maximum number of bytes that can be base64 encoded in a single operation.
// This limit prevents excessive memory allocation and ensures reasonable processing times.
// The limit of 10MB is sufficient for all I2P protocol needs including router infos,
// destinations, and lease sets, while preventing potential DoS through memory exhaustion.
const MAX_ENCODE_SIZE = 10 * 1024 * 1024 // 10 MB

// MAX_DECODE_SIZE defines the maximum length of a base64 string accepted by DecodeStringSafe.
// This is derived from MAX_ENCODE_SIZE to ensure decoded output cannot exceed the encode limit.
const MAX_DECODE_SIZE = ((MAX_ENCODE_SIZE + 2) / 3) * 4

// I2PEncoding provides the standard base64 encoder/decoder instance for all I2P components.
// This encoding instance is pre-configured with the I2P-specific alphabet and optimizes performance
// by reusing the same encoder across multiple operations. It handles the complex character mapping
// required for I2P network compatibility while maintaining standard base64 semantics.
// The instance is thread-safe and can be used concurrently across goroutines.
var I2PEncoding *b64.Encoding = b64.NewEncoding(I2PEncodeAlphabet)
