// Package lease_set constants
package lease_set

import "github.com/samber/oops"

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

	// LEASE_SET_MAX_LEASES is the maximum number of leases in a LeaseSet per spec.
	LEASE_SET_MAX_LEASES = 16
)

// Errors
var (
	// ErrNoLeases is returned when a LeaseSet has no leases and an
	// expiration-related operation is called.
	ErrNoLeases = oops.Errorf("lease set has no leases")

	// ErrTrailingData is returned when a LeaseSet has trailing bytes after the
	// signature. The I2P spec prohibits excess data in structures.
	ErrTrailingData = oops.Errorf("LeaseSet has trailing data after signature")

	// ErrNonElGamalEncryptionKey is returned when a LeaseSet v1 is constructed
	// with an encryption key that is not an ElGamal public key. LeaseSet v1
	// mandates ElGamal encryption; non-ElGamal crypto types are only valid in
	// LeaseSet2.
	ErrNonElGamalEncryptionKey = oops.Errorf("LeaseSet v1 requires ElGamal encryption key")

	// ErrAllZeroEncryptionKey is returned when a LeaseSet's encryption key is
	// all zero bytes, which is cryptographically invalid.
	ErrAllZeroEncryptionKey = oops.Errorf("encryption key is all zeros (cryptographically invalid)")
)
