// Package encrypted_leaseset implements the I2P EncryptedLeaseSet common data structure
package encrypted_leaseset

const (
	// ENCRYPTED_LEASESET_TYPE is the database store type identifier for EncryptedLeaseSet
	// as specified in I2P Common Structures specification
	// https://geti2p.net/spec/common-structures#encryptedleaseset
	ENCRYPTED_LEASESET_TYPE uint8 = 5

	// Size constants for minimum and field sizes

	// ENCRYPTED_LEASESET_MIN_SIZE is the minimum size in bytes for a valid EncryptedLeaseSet.
	// Calculation: Destination(387) + published(4) + expires(2) + flags(2) +
	//              options(2) + cookie(32) + inner_len(2) + encrypted(1+) + sig(64+)
	// Minimum: 387 + 4 + 2 + 2 + 2 + 32 + 2 + 1 + 64 = 496 bytes
	ENCRYPTED_LEASESET_MIN_SIZE int = 496

	// Field size constants

	// ENCRYPTED_LEASESET_COOKIE_SIZE is the size of the cookie field (32 bytes)
	ENCRYPTED_LEASESET_COOKIE_SIZE int = 32

	// ENCRYPTED_LEASESET_INNER_LENGTH_SIZE is the size of the inner length field (2 bytes)
	ENCRYPTED_LEASESET_INNER_LENGTH_SIZE int = 2

	// ENCRYPTED_LEASESET_PUBLISHED_SIZE is the size of the published timestamp field (4 bytes)
	ENCRYPTED_LEASESET_PUBLISHED_SIZE int = 4

	// ENCRYPTED_LEASESET_EXPIRES_SIZE is the size of the expires offset field (2 bytes)
	ENCRYPTED_LEASESET_EXPIRES_SIZE int = 2

	// ENCRYPTED_LEASESET_FLAGS_SIZE is the size of the flags field (2 bytes)
	ENCRYPTED_LEASESET_FLAGS_SIZE int = 2

	// Flag constants (reuses LeaseSet2 flag semantics)

	// ENCRYPTED_LEASESET_FLAG_OFFLINE_KEYS indicates offline signature is present (bit 0)
	ENCRYPTED_LEASESET_FLAG_OFFLINE_KEYS uint16 = 1 << 0

	// ENCRYPTED_LEASESET_FLAG_UNPUBLISHED indicates the lease set is unpublished (bit 1)
	ENCRYPTED_LEASESET_FLAG_UNPUBLISHED uint16 = 1 << 1

	// ENCRYPTED_LEASESET_FLAG_BLINDED indicates blinded key is used (bit 2)
	// This flag is always set for EncryptedLeaseSet as blinding is required
	ENCRYPTED_LEASESET_FLAG_BLINDED uint16 = 1 << 2

	// Expiration limits

	// ENCRYPTED_LEASESET_MAX_EXPIRES_OFFSET is the maximum expiration offset in seconds (65535)
	// Same as LeaseSet2 (approximately 18.2 hours)
	ENCRYPTED_LEASESET_MAX_EXPIRES_OFFSET uint16 = 65535

	// ENCRYPTED_LEASESET_TYPICAL_MAX_EXPIRES is the typical maximum expiration offset (660 seconds)
	// Same as LeaseSet2 (11 minutes)
	ENCRYPTED_LEASESET_TYPICAL_MAX_EXPIRES uint16 = 660

	// Minimum signature size for Ed25519 (most common signature type)
	ENCRYPTED_LEASESET_MIN_SIGNATURE_SIZE int = 64

	// ENCRYPTED_LEASESET_MIN_DESTINATION_SIZE is the minimum size for a destination (387 bytes)
	// Includes ElGamal encryption key (256 bytes) + Ed25519 signing key (32 bytes) +
	// padding (96 bytes) + certificate (3 bytes minimum)
	ENCRYPTED_LEASESET_MIN_DESTINATION_SIZE int = 387
)
