// Package destination implements the I2P Destination common data structure according to specification version 0.9.67.
//
// A Destination represents a unique cryptographic identity in the I2P network, consisting of
// public encryption and signing keys along with a certificate. Destinations are used to identify
// services, routers, and endpoints within I2P.
//
// # Overview
//
// A Destination contains:
//
//   - Public encryption key (ElGamal or X25519)
//   - Public signing key (DSA, ECDSA, EdDSA, or RSA)
//   - Certificate (typically a KEY certificate with cryptographic parameters)
//   - Optional padding for alignment
//
// # Safe Constructors
//
// The package provides validated constructors for creating destinations:
//
//	// Create from KeysAndCert
//	dest, err := destination.NewDestination(keysAndCert)
//	if err != nil {
//	    return err
//	}
//
//	// Parse from bytes
//	dest, remainder, err := destination.NewDestinationFromBytes(data)
//	if err != nil {
//	    return err
//	}
//
// # Validation
//
// Destinations support validation to ensure proper initialization:
//
//	// Full validation
//	if err := dest.Validate(); err != nil {
//	    return err
//	}
//
//	// Boolean check
//	if !dest.IsValid() {
//	    return errors.New("invalid destination")
//	}
//
// # Encoding Formats
//
// Destinations can be encoded in multiple formats:
//
//	// Base64 encoding (standard I2P format)
//	base64Str, err := dest.Base64()
//	if err != nil {
//	    return err
//	}
//
//	// Base32 address (human-readable .i2p address)
//	address, err := dest.Base32Address()
//	if err != nil {
//	    return err
//	}
//
//	// Raw bytes
//	bytes, err := dest.Bytes()
//	if err != nil {
//	    return err
//	}
//
// # Parsing from Bytes
//
// Destinations can be safely parsed from byte streams:
//
//	dest, remainder, err := destination.ReadDestination(data)
//	if err != nil {
//	    return err
//	}
//	if !dest.IsValid() {
//	    return errors.New("invalid destination")
//	}
//
// # Key Access
//
// Public keys can be accessed safely:
//
//	// Get public encryption key
//	pubKey, err := dest.PublicKey()
//	if err != nil {
//	    return err
//	}
//
//	// Get signing public key
//	sigKey, err := dest.SigningPublicKey()
//	if err != nil {
//	    return err
//	}
//
//	// Get certificate
//	cert := dest.Certificate()
//
// # Best Practices
//
//   - Always use NewDestination() or NewDestinationFromBytes() constructors
//   - Validate destinations after parsing from untrusted sources
//   - Use error-checking methods when accessing keys and encoding
//   - Prefer Ed25519/X25519 for new destinations (modern cryptography)
//
// # Specification
//
// Reference: https://geti2p.net/spec/common-structures#destination
//
// This implementation follows I2P specification version 0.9.67 and provides
// comprehensive validation and error handling for all destination operations.
package destination
