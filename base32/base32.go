// Package base32 implements utilities for encoding and decoding text using I2P's alphabet.
//
// ADDED: This package provides I2P-specific base32 encoding/decoding functionality using
// RFC 3548 with lowercase characters as specified by the I2P protocol. The implementation
// supports encoding binary data to human-readable strings for I2P destinations, router
// identifiers, and other network components that require base32 representation.
//
// ADDED: Key features:
// - I2P-compatible base32 alphabet (excludes confusing characters)
// - Consistent lowercase encoding for .b32.i2p domain compatibility
// - Error handling for invalid input data during decoding operations
// - High-performance encoding/decoding suitable for network operations
//
// ADDED: Common usage patterns:
//   encoded := base32.EncodeToString(binaryData)
//   decoded, err := base32.DecodeString(encodedString)
package base32
