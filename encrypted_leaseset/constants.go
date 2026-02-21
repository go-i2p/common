// Package encrypted_leaseset implements the I2P EncryptedLeaseSet common data structure
package encrypted_leaseset

const (
	// ENCRYPTED_LEASESET_TYPE is the database store type identifier for EncryptedLeaseSet (type 5).
	// https://geti2p.net/spec/common-structures#encryptedleaseset
	ENCRYPTED_LEASESET_TYPE uint8 = 5

	// ENCRYPTED_LEASESET_DBSTORE_TYPE is prepended to serialized data before signing/verification.
	ENCRYPTED_LEASESET_DBSTORE_TYPE byte = 0x05

	// ENCRYPTED_LEASESET_MIN_SIZE is the minimum wire size in bytes:
	// sig_type(2) + blinded_key(32 min for Ed25519) + published(4) + expires(2) +
	// flags(2) + len(2) + encrypted(1 min) + signature(64 min for Ed25519) = 109
	ENCRYPTED_LEASESET_MIN_SIZE int = 109

	// Field size constants

	// ENCRYPTED_LEASESET_SIGTYPE_SIZE is the size of the sig_type field (2 bytes).
	ENCRYPTED_LEASESET_SIGTYPE_SIZE int = 2

	// ENCRYPTED_LEASESET_PUBLISHED_SIZE is the size of the published timestamp field (4 bytes).
	ENCRYPTED_LEASESET_PUBLISHED_SIZE int = 4

	// ENCRYPTED_LEASESET_EXPIRES_SIZE is the size of the expires offset field (2 bytes).
	ENCRYPTED_LEASESET_EXPIRES_SIZE int = 2

	// ENCRYPTED_LEASESET_FLAGS_SIZE is the size of the flags field (2 bytes).
	ENCRYPTED_LEASESET_FLAGS_SIZE int = 2

	// ENCRYPTED_LEASESET_INNER_LENGTH_SIZE is the size of the inner length field (2 bytes).
	ENCRYPTED_LEASESET_INNER_LENGTH_SIZE int = 2

	// Flag constants — per spec: bit 0 = offline keys, bit 1 = unpublished, bits 15-2 reserved.

	// ENCRYPTED_LEASESET_FLAG_OFFLINE_KEYS indicates offline signature is present (bit 0).
	ENCRYPTED_LEASESET_FLAG_OFFLINE_KEYS uint16 = 1 << 0

	// ENCRYPTED_LEASESET_FLAG_UNPUBLISHED indicates the lease set is not stored in netdb (bit 1).
	ENCRYPTED_LEASESET_FLAG_UNPUBLISHED uint16 = 1 << 1

	// ENCRYPTED_LEASESET_RESERVED_FLAGS_MASK covers bits 15-2 which must be zero per spec.
	ENCRYPTED_LEASESET_RESERVED_FLAGS_MASK uint16 = 0xFFFC

	// Expiration limits

	// ENCRYPTED_LEASESET_MAX_EXPIRES_OFFSET is the maximum expiration offset in seconds.
	ENCRYPTED_LEASESET_MAX_EXPIRES_OFFSET uint16 = 65535

	// ENCRYPTED_LEASESET_TYPICAL_MAX_EXPIRES is a typical maximum (11 minutes).
	ENCRYPTED_LEASESET_TYPICAL_MAX_EXPIRES uint16 = 660

	// ENCRYPTED_LEASESET_MIN_SIGNATURE_SIZE is the minimum signature size (Ed25519 = 64 bytes).
	ENCRYPTED_LEASESET_MIN_SIGNATURE_SIZE int = 64

	// ENCRYPTED_LEASESET_MIN_ENCRYPTED_SIZE is the minimum encrypted inner data size:
	// outerSalt(32) + authType(1) + innerSalt(32) + plaintext(1 min) = 66 bytes.
	// Per the I2P spec, encrypted data uses a two-layer ChaCha20 scheme with 32-byte salts.
	ENCRYPTED_LEASESET_MIN_ENCRYPTED_SIZE int = 66

	// ENCRYPTED_LEASESET_OUTER_SALT_SIZE is the size of the outer salt in the encrypted data (32 bytes).
	ENCRYPTED_LEASESET_OUTER_SALT_SIZE int = 32

	// ENCRYPTED_LEASESET_INNER_SALT_SIZE is the size of the inner salt in the Layer 1 plaintext (32 bytes).
	ENCRYPTED_LEASESET_INNER_SALT_SIZE int = 32

	// Auth type constants for per-client authorization in Layer 1.

	// ENCRYPTED_LEASESET_AUTH_TYPE_NONE indicates no per-client authorization (type 0).
	ENCRYPTED_LEASESET_AUTH_TYPE_NONE byte = 0

	// ENCRYPTED_LEASESET_AUTH_TYPE_DH indicates per-client DH authorization (type 1).
	// Not yet implemented.
	ENCRYPTED_LEASESET_AUTH_TYPE_DH byte = 1

	// ENCRYPTED_LEASESET_AUTH_TYPE_PSK indicates per-client PSK authorization (type 2).
	// Not yet implemented.
	ENCRYPTED_LEASESET_AUTH_TYPE_PSK byte = 2
)
