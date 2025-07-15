// Package base64 implements I2P-specific base64 encoding and decoding utilities.
//
// This package provides base64 functionality tailored for the I2P (Invisible Internet Project) network,
// implementing a modified RFC 4648 base64 alphabet that ensures compatibility with I2P protocols and
// addressing schemes. The key modifications replace problematic characters: "/" becomes "~" to avoid
// filesystem conflicts, and "+" becomes "-" for URL-safe encoding without percent-encoding requirements.
//
// The package is essential for handling I2P destination addresses, router identifiers, cryptographic
// key material, and binary data serialization throughout the I2P ecosystem. All encoding operations
// maintain standard base64 semantics while using the I2P-specific character set.
//
// Usage patterns:
//   - Encoding binary data for I2P network transmission
//   - Generating .b64.i2p destination addresses
//   - Converting cryptographic keys to string representation
//   - Serializing router information and network database entries
//
// The implementation emphasizes performance and thread safety, providing reusable encoder instances
// that can be safely used across concurrent operations without synchronization overhead.
package base64
