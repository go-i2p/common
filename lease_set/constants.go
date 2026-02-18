// Package lease_set constants
package lease_set

// Sizes of various structures in an I2P LeaseSet
const (
	// LEASE_SET_PUBKEY_SIZE is the size of the ElGamal encryption public key (256 bytes).
	LEASE_SET_PUBKEY_SIZE = 256

	// LEASE_SET_DEFAULT_SIGNING_KEY_SIZE is the default signing public key size (128 bytes for DSA-SHA1).
	// For key certificate destinations, the actual size is determined by the certificate.
	LEASE_SET_DEFAULT_SIGNING_KEY_SIZE = 128

	// LEASE_SET_DEFAULT_SIG_SIZE is the default signature size (40 bytes for DSA-SHA1).
	// For key certificate destinations, the actual size is determined by the certificate.
	LEASE_SET_DEFAULT_SIG_SIZE = 40

	// LEASE_SET_SPK_SIZE is the legacy name for LEASE_SET_DEFAULT_SIGNING_KEY_SIZE.
	// Deprecated: Use LEASE_SET_DEFAULT_SIGNING_KEY_SIZE instead.
	LEASE_SET_SPK_SIZE = LEASE_SET_DEFAULT_SIGNING_KEY_SIZE

	// LEASE_SET_SIG_SIZE is the legacy name for LEASE_SET_DEFAULT_SIG_SIZE.
	// Deprecated: Use LEASE_SET_DEFAULT_SIG_SIZE instead.
	LEASE_SET_SIG_SIZE = LEASE_SET_DEFAULT_SIG_SIZE
)
