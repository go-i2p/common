// Package common provides I2P protocol common data structures and utilities.
//
// This library implements type-safe I2P network protocol data structures according
// to specification version 0.9.67, with comprehensive validation and error handling.
//
// # Overview
//
// The go-i2p/common package provides fundamental building blocks for I2P applications:
//
//   - Data primitives (Integer, String, Date, Hash, Mapping)
//   - Cryptographic structures (Certificate, Signature, KeyCertificate)
//   - Network identities (Destination, RouterIdentity, RouterInfo)
//   - Tunnel management (Lease, LeaseSet, EncryptedLeaseSet)
//   - Encoding utilities (Base32, Base64)
//
// # Design Philosophy
//
// This library prioritizes safety and correctness:
//
//   - All types provide safe constructors with validation
//   - Zero-value types are checked and rejected
//   - Errors are returned explicitly, never ignored
//   - Stream parsing supports efficient multi-value reads
//   - Comprehensive test coverage (>85%) ensures reliability
//
// # Constructor Pattern
//
// All complex types follow a consistent constructor pattern:
//
//	// Primary constructor with validation
//	obj, err := NewType(params...)
//	if err != nil {
//	    return err
//	}
//
//	// Parse from bytes
//	obj, remainder, err := NewTypeFromBytes(data)
//	if err != nil {
//	    return err
//	}
//
//	// Read from stream (no constructor - returns parsed type)
//	obj, remainder, err := ReadType(data)
//	if err != nil {
//	    return err
//	}
//
// # Validation Pattern
//
// All types implement validation methods:
//
//	// Comprehensive validation with detailed errors
//	if err := obj.Validate(); err != nil {
//	    return fmt.Errorf("validation failed: %w", err)
//	}
//
//	// Boolean convenience method
//	if !obj.IsValid() {
//	    return errors.New("object is invalid")
//	}
//
// # Safe Accessors
//
// Types provide both legacy and safe accessor methods:
//
//	// Legacy accessor (may return zero on error)
//	value := integer.Int()
//
//	// Safe accessor (returns error)
//	value, err := integer.IntSafe()
//	if err != nil {
//	    return err
//	}
//
// # Package Organization
//
// The library is organized into focused packages:
//
//   - data: Primitive I2P data types
//   - base32/base64: I2P-specific encoding
//   - certificate: Certificate structures
//   - key_certificate: Key-specific certificates
//   - keys_and_cert: Combined public keys with certificates
//   - destination: Network identities
//   - router_identity: Router identities
//   - router_address: Router network addresses
//   - router_info: Complete router information
//   - lease: Individual tunnel leases
//   - lease_set: Standard lease sets
//   - lease_set2: Extended lease sets
//   - encrypted_leaseset: Encrypted lease sets
//   - meta_leaseset: Meta lease sets
//   - offline_signature: Offline signing support
//   - signature: Digital signatures
//   - session_tag: Session tags for encryption
//   - session_key: Session keys
//
// # Example Usage
//
// Creating a destination:
//
//	// Generate keys
//	keyCert, _ := key_certificate.NewEd25519X25519KeyCertificate()
//	pubKey, privKey := /* generate Ed25519 key pair */
//	encKey, encPrivKey := /* generate X25519 key pair */
//
//	// Create KeysAndCert
//	kac, err := keys_and_cert.NewKeysAndCert(keyCert, encKey, nil, pubKey)
//	if err != nil {
//	    return err
//	}
//
//	// Create Destination
//	dest, err := destination.NewDestination(kac)
//	if err != nil {
//	    return err
//	}
//
//	// Encode as Base32 address
//	address, err := dest.Base32Address()
//	fmt.Printf("I2P address: %s.b32.i2p\n", address)
//
// Parsing from bytes:
//
//	// Parse destination from bytes
//	dest, remainder, err := destination.ReadDestination(data)
//	if err != nil {
//	    return err
//	}
//
//	// Validate parsed data
//	if err := dest.Validate(); err != nil {
//	    return fmt.Errorf("invalid destination: %w", err)
//	}
//
// # Migration from Legacy Code
//
// This library maintains backward compatibility while adding safe constructors:
//
//	// OLD (unsafe):
//	i := data.Integer(someBytes)
//	value := i.Int()  // May return 0 on error
//
//	// NEW (safe):
//	i, err := data.NewIntegerFromBytes(someBytes)
//	if err != nil {
//	    return err
//	}
//	value, err := i.IntSafe()
//	if err != nil {
//	    return err
//	}
//
// # Specification Compliance
//
// Reference: https://geti2p.net/spec/common-structures
//
// This implementation follows I2P specification version 0.9.67 and is designed
// for use in I2P routers, clients, and utilities.
//
// # Version Information
//
// Use the package constants to check specification version:
//
//	fmt.Printf("I2P Spec Version: %s\n", common.I2P_SPEC_VERSION)
//	fmt.Printf("Major.Minor.Patch: %d.%d.%d\n",
//	    common.I2P_SPEC_MAJOR,
//	    common.I2P_SPEC_MINOR,
//	    common.I2P_SPEC_PATCH)
package common
