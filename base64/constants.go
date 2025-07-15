// Package base64 constants
package base64

// I2PEncodeAlphabet defines the I2P-specific base64 character set used throughout the network.
// This alphabet follows RFC 4648 standard base64 encoding with two critical modifications:
// - "/" is replaced with "~" to avoid filesystem path conflicts
// - "+" is replaced with "-" to ensure URL-safe encoding without percent-encoding
// The alphabet maintains the standard ordering: A-Z (0-25), a-z (26-51), 0-9 (52-61), - (62), ~ (63).
// This encoding is essential for I2P destination addresses, router identifiers, and network data structures.
// Example usage: Used in .b64.i2p addresses and binary data serialization across I2P protocols.
const I2PEncodeAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-~"
