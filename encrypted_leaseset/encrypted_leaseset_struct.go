// Package encrypted_leaseset implements the I2P EncryptedLeaseSet common data structure
package encrypted_leaseset

import (
	"github.com/go-i2p/common/data"
	"github.com/go-i2p/common/destination"
	"github.com/go-i2p/common/offline_signature"
	sig "github.com/go-i2p/common/signature"
)

// EncryptedLeaseSet represents an encrypted I2P LeaseSet2 (Database Store Type 5).
// Introduced in I2P 0.9.38, it provides privacy and forward secrecy by encrypting
// the destination, encryption keys, and leases. The blinded destination prevents
// correlation between different encrypted lease sets of the same service.
//
// The encrypted inner data contains a complete LeaseSet2 structure encrypted with
// a per-client symmetric key derived from the cookie and shared secret.
//
// Wire Format:
//
//	blinded_destination (387+ bytes) - Derived from actual destination using blinding factor
//	published (4 bytes)               - Timestamp in seconds since epoch
//	expires (2 bytes)                 - Expiration offset from published in seconds
//	flags (2 bytes)                   - Same semantics as LeaseSet2
//	[offline_signature] (variable)    - Present if flags bit 0 set
//	options (2+ bytes)                - Mapping for service discovery
//	cookie (32 bytes)                 - Anti-replay and key derivation
//	inner_length (2 bytes)            - Length of encrypted inner data
//	encrypted_inner_data (variable)   - Encrypted LeaseSet2 structure
//	signature (variable)              - By blinded destination or transient key
//
// Security Properties:
//   - Forward secrecy: Cookie rotation prevents past data decryption
//   - Unlinkability: Blinded destination differs across publications
//   - Anti-replay: Cookie prevents reuse of captured encrypted data
//   - Client isolation: Each client can use unique symmetric key
//
// https://geti2p.net/spec/common-structures#encryptedleaseset
type EncryptedLeaseSet struct {
	// Blinded destination - derived from actual destination using blinding factor.
	// This prevents correlation between different EncryptedLeaseSet instances
	// for the same service.
	blindedDestination destination.Destination

	// Published timestamp (4 bytes, seconds since Unix epoch).
	// Used as base time for expiration calculation.
	published uint32

	// Expiration offset from published (2 bytes, seconds).
	// Maximum value is 65535 (approximately 18.2 hours).
	expires uint16

	// Flags field (2 bytes) - same semantics as LeaseSet2:
	//   Bit 0: Offline signature present
	//   Bit 1: Unpublished (not stored in network database)
	//   Bit 2: Blinded key used (always set for EncryptedLeaseSet)
	flags uint16

	// Optional offline signature (present if flags bit 0 set).
	// Allows separation of long-term identity key from signing operations.
	offlineSignature *offline_signature.OfflineSignature

	// Options mapping for service discovery (2+ bytes, sorted by key).
	// Can contain metadata like service type, version, or capabilities.
	options data.Mapping

	// Cookie for anti-replay and key derivation (32 bytes).
	// Used to derive symmetric encryption key via HKDF or similar KDF.
	// Must be included in authorization to access the encrypted data.
	cookie [32]byte

	// Length of encrypted inner data (2 bytes).
	// Allows efficient buffer allocation before decryption.
	innerLength uint16

	// Encrypted inner lease set data (contains LeaseSet2-like structure).
	// Decryption requires:
	//   1. Correct cookie (matches this field)
	//   2. Recipient's private key (for ECDH shared secret)
	//   3. Key derivation (HKDF-SHA256 from cookie + shared secret)
	//   4. Authenticated decryption (ChaCha20-Poly1305 or AES-256-GCM)
	encryptedInnerData []byte

	// Signature by blinded destination or transient key.
	// Signs all preceding data prepended with database store type (0x05).
	signature sig.Signature
}
