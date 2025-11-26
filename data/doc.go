// Package data implements I2P common data structures according to specification version 0.9.67.
//
// This package provides fundamental data types used throughout the I2P network protocol,
// including safe constructors and validators to prevent common programming errors.
//
// # Overview
//
// The data package contains low-level I2P data structures that are building blocks
// for higher-level protocol components:
//
//   - Integer: Variable-length big-endian integers
//   - I2PString: Length-prefixed UTF-8 strings (max 255 bytes)
//   - Date: 64-bit millisecond timestamps (rolls over in 2106)
//   - Hash: 32-byte SHA-256 hashes
//   - Mapping: Key-value property maps
//   - MappingValues: Type-safe key-value pair collections
//
// # Safe Constructors
//
// All types provide safe constructors that validate input and return errors
// rather than panicking or producing invalid data:
//
//	// Integer construction with validation
//	i, err := data.NewIntegerFromBytes(someBytes)
//	if err != nil {
//	    return err
//	}
//	value, err := i.IntSafe()  // Returns error instead of defaulting to 0
//
//	// String construction with UTF-8 validation
//	str, err := data.NewI2PString("hello")
//	if err != nil {
//	    return err
//	}
//	content, err := str.DataSafe()  // Safe accessor with error handling
//
//	// Hash construction from bytes
//	hash, err := data.NewHashFromSlice(hashBytes)
//	if err != nil {
//	    return err
//	}
//
//	// Date construction with validation
//	date, err := data.NewDateFromUnix(timestamp)
//	if err != nil {
//	    return err
//	}
//
// # Zero-Value Safety
//
// All types provide methods to check for zero/invalid values:
//
//	if integer.IsZero() {
//	    // Handle zero integer
//	}
//
//	if hash.IsZero() {
//	    // Handle zero hash
//	}
//
//	if date.IsZero() {
//	    // Handle undefined date
//	}
//
// # Validation
//
// Types provide Validate() and IsValid() methods for checking integrity:
//
//	// Validate mapping structure and all key-value pairs
//	if err := mapping.Validate(); err != nil {
//	    return err
//	}
//
//	// Boolean validation check
//	if !mapping.IsValid() {
//	    return errors.New("invalid mapping")
//	}
//
// # Encoding and Decoding
//
// The package provides safe integer encoding with overflow checks:
//
//	// Encode with size validation
//	encoded, err := data.EncodeIntN(12345, 4)  // validates value fits in 4 bytes
//	if err != nil {
//	    return err
//	}
//
//	// Decode with length validation
//	decoded, err := data.DecodeIntN(encoded)
//	if err != nil {
//	    return err
//	}
//
// # Stream Parsing
//
// Many types support stream-oriented parsing for efficient multi-value reads:
//
//	hash1, remaining, err := data.ReadHash(data)
//	if err != nil {
//	    return err
//	}
//	hash2, remaining, err := data.ReadHash(remaining)
//	// ... continue parsing
//
// # Best Practices
//
//   - Always use safe constructors (NewXxx) for untrusted input
//   - Check IsValid() or Validate() after parsing from bytes
//   - Use safe accessor methods (xxxSafe) when error handling is critical
//   - Validate sizes before encoding to prevent DoS attacks
//
// # Specification
//
// Reference: https://geti2p.net/spec/common-structures
//
// This implementation follows I2P specification version 0.9.67 and provides
// backward-compatible safe constructors while maintaining the existing API.
package data
