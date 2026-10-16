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
// # How the Pieces Fit Together
//
// I2P is an anonymous network: every participant is identified by a
// cryptographic identity, and messages are routed through a series of
// tunnels. These data structures are the shared vocabulary that routers and
// clients use to talk to each other. They build on each other in layers:
//
//  1. Primitives (data): the raw wire types — integers, strings, dates,
//     hashes, and key-value maps. Everything else is built from these.
//
//  2. Keys and certificates (certificate, key_certificate, keys_and_cert):
//     a public key plus a certificate that describes how to use it.
//
//  3. Identities (destination, router_identity, router_info): a Destination
//     is a cryptographic identity for a service or endpoint. A
//     RouterIdentity is the same shape, but for a router. A RouterInfo
//     bundles a RouterIdentity with the router's network addresses and a
//     signature, and is what routers publish to the network.
//
//  4. Leases (lease, lease_set, lease_set2, encrypted_leaseset): a Lease
//     says "this tunnel endpoint is valid until this time." A LeaseSet
//     groups the leases for one destination. An EncryptedLeaseSet hides the
//     destination and its tunnels behind encryption, which is what hidden
//     services use.
//
// If you are new to I2P, start with the data package, then read
// destination, then lease_set2, then encrypted_leaseset. Each package's
// documentation links to the relevant section of the I2P specification.
//
// # Design Philosophy
//
// This library prioritizes safety and correctness:
//
//   - All types provide safe constructors with validation
//   - Zero-value types are checked and rejected
//   - Errors are returned explicitly, never ignored
//   - Stream parsing supports efficient multi-value reads
//   - Comprehensive test coverage (87.7% of statements across all packages;
//     individual packages range from ~70% to 100%) ensures reliability
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
//	// Parse from bytes. The arity of the *FromBytes constructors varies by type:
//	// fixed-size types return (obj, err), for example data.NewIntegerFromBytes,
//	// data.NewI2PStringFromBytes, session_tag.NewSessionTagFromBytes and
//	// signature.NewSignatureFromBytes; stream types also return the unconsumed
//	// bytes, for example destination.NewDestinationFromBytes and
//	// lease.NewLeaseFromBytes:
//	//
//	obj, err := NewTypeFromBytes(data)              // fixed-size types
//	obj, remainder, err := NewTypeFromBytes(data)   // stream types
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
//	// Create KeysAndCert. Padding is required: it must be exactly
//	// KEYS_AND_CERT_DATA_SIZE (384) minus the public key size minus the
//	// inline signing key size, where the inline signing key size is the
//	// declared signing public key size capped at KEYS_AND_CERT_SPK_SIZE (128).
//	// For Ed25519 + X25519 that is 384 - 32 - 32 = 320 bytes.
//	padding := make([]byte, 320)
//	kac, err := keys_and_cert.NewKeysAndCert(keyCert, encKey, padding, pubKey)
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
//	// Encode as Base32 address (the returned string already ends in ".b32.i2p")
//	address, err := dest.Base32Address()
//	fmt.Printf("I2P address: %s\n", address)
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
// ## Known Specification Deviations / Supported Cryptographic Scope
//
// This library intentionally does not support signing or verification with the
// following legacy cryptographic algorithms, which are deprecated in the I2P
// specification as of version 0.9.58 (the Ed25519 mandate release):
//
// - **DSA-SHA1** (signing type 0): structures using this algorithm parse
//   correctly, but `VerifySignature()` and related methods return an explicit
//   "legacy unsupported signature type" error.
// - **RSA-SHA256-2048** (signing type 4), **RSA-SHA384-3072** (type 5),
//   **RSA-SHA512-4096** (type 6): rejected outright, unlike DSA-SHA1.
//   `ReadRouterIdentity`/`NewRouterIdentity` and `ReadDestination`/
//   `NewDestination` fail with "signing key type N ... is not permitted"
//   before any verification is attempted.
// - **Ed25519ph** (signing type 8): offline/transient use only; not supported
//   for RouterIdentity or Destination key certificates.
// - **RedDSA** (signing type 11): permitted for Destinations and encrypted
//   lease sets, but rejected for RouterIdentities.
//
// Legacy LeaseSet (v1) structures with a NULL certificate (implying DSA-SHA1)
// are rejected with `ErrLegacyCryptoNotSupported` rather than parsed, as they
// cannot be verified with modern algorithms.
//
// The remaining specification algorithms — Ed25519, ECDSA P256/P384/P521,
// RedDSA and X25519 — are fully supported for both parsing and cryptographic
// operations. The MLKEM+X25519 hybrid key types (5/6/7) are supported for
// parsing and size accounting only: the X25519 component is usable, while the
// post-quantum ML-KEM component has no implementation in
// github.com/go-i2p/crypto, so no hybrid key agreement or decryption is
// performed. Likewise, RouterInfo creation (see the router_info package) is
// currently limited to Ed25519 (type 7).
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
