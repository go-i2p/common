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
	// OFFLINE_SIGNATURE_MIN_SIZE defines the minimum byte length of an OfflineSignature.
	// This includes: 4 bytes (expires) + 2 bytes (sigtype) + minimum key size + minimum signature size.
	// The actual minimum depends on signature types, but EdDSA (type 7) gives us 4+2+32+64 = 102 bytes.
	OFFLINE_SIGNATURE_MIN_SIZE = 102

	// EXPIRES_SIZE defines the byte length of the expires field (4-byte timestamp).
	// Seconds since the epoch, rolls over in 2106.
	EXPIRES_SIZE = 4

	// SIGTYPE_SIZE defines the byte length of the signature type field.
	SIGTYPE_SIZE = 2
)
