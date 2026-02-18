// Package offline_signature implements the I2P OfflineSignature common data structure
// according to specification version 0.9.67.
//
// OfflineSignature is an optional part of LeaseSet2Header, and is also used in
// streaming and I2CP protocols. It allows a destination to use offline signing keys
// for enhanced security by separating the long-term signing key from the transient
// signing key used for daily operations.
//
// Specification: https://geti2p.net/spec/common-structures#offlinesignature
// Introduced: I2P version 0.9.38 (Proposal 123)
package offline_signature

const (
	// OFFLINE_SIGNATURE_EDDSA_SIZE is the total byte length of an OfflineSignature when both
	// the transient key and the destination use EdDSA-SHA512-Ed25519 (type 7):
	// 4 (expires) + 2 (sigtype) + 32 (Ed25519 public key) + 64 (Ed25519 signature) = 102 bytes.
	OFFLINE_SIGNATURE_EDDSA_SIZE = 102

	// OFFLINE_SIGNATURE_MIN_SIZE is the byte length of an EdDSA-only OfflineSignature (102 bytes).
	// Deprecated: This name is misleading because smaller valid OfflineSignatures exist when
	// mixing signature types (e.g., Ed25519 transient + DSA_SHA1 destination = 78 bytes).
	// Use OFFLINE_SIGNATURE_EDDSA_SIZE for clarity.
	OFFLINE_SIGNATURE_MIN_SIZE = OFFLINE_SIGNATURE_EDDSA_SIZE

	// EXPIRES_SIZE defines the byte length of the expires field (4-byte timestamp).
	// Seconds since the epoch, rolls over in 2106.
	EXPIRES_SIZE = 4

	// SIGTYPE_SIZE defines the byte length of the signature type field.
	SIGTYPE_SIZE = 2
)
