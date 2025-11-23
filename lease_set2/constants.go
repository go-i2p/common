// Package lease_set2 implements the I2P LeaseSet2 common data structure
package lease_set2

// LeaseSet2 Structure Size Constants
// These constants define the minimum and maximum sizes for LeaseSet2 components
// according to I2P specification 0.9.67.
const (
	// LEASESET2_MIN_SIZE is the absolute minimum size for a LeaseSet2 structure.
	// This assumes: LeaseSet2Header (395 bytes) + empty options (2 bytes) +
	// 1 encryption key (5 bytes header + 32 bytes X25519) + 0 leases (1 byte) + signature (64 bytes EdDSA)
	// = 395 + 2 + 5 + 32 + 1 + 64 = 499 bytes minimum
	LEASESET2_MIN_SIZE = 499

	// LEASESET2_HEADER_MIN_SIZE is the minimum size of LeaseSet2Header without offline signature.
	// Destination (387 bytes) + published (4 bytes) + expires (2 bytes) + flags (2 bytes)
	// = 395 bytes
	LEASESET2_HEADER_MIN_SIZE = 395

	// LEASESET2_MIN_DESTINATION_SIZE is the minimum size for a valid I2P Destination.
	// This is 387 bytes: 384 bytes for KeysAndCert data + minimum 3 bytes for certificate.
	LEASESET2_MIN_DESTINATION_SIZE = 387

	// LEASESET2_PUBLISHED_SIZE is the size of the published timestamp field (4 bytes, seconds since epoch).
	LEASESET2_PUBLISHED_SIZE = 4

	// LEASESET2_EXPIRES_SIZE is the size of the expires offset field (2 bytes, offset from published in seconds).
	// Maximum offset is 65535 seconds (18.2 hours), but typically limited to ~660 seconds (11 minutes).
	LEASESET2_EXPIRES_SIZE = 2

	// LEASESET2_FLAGS_SIZE is the size of the flags field (2 bytes).
	LEASESET2_FLAGS_SIZE = 2

	// LEASESET2_ENCRYPTION_KEY_TYPE_SIZE is the size of each encryption key type field (2 bytes).
	LEASESET2_ENCRYPTION_KEY_TYPE_SIZE = 2

	// LEASESET2_ENCRYPTION_KEY_LENGTH_SIZE is the size of each encryption key length field (2 bytes).
	LEASESET2_ENCRYPTION_KEY_LENGTH_SIZE = 2

	// LEASESET2_MAX_LEASES is the maximum number of Lease2 structures allowed in a LeaseSet2 (16).
	// This is the same limit as legacy LeaseSet.
	LEASESET2_MAX_LEASES = 16

	// LEASESET2_MAX_ENCRYPTION_KEYS is a reasonable upper limit for the number of encryption keys.
	// While the spec doesn't define a hard maximum, practical implementations support 1-4 keys.
	LEASESET2_MAX_ENCRYPTION_KEYS = 16
)

// LeaseSet2 Flags Constants
// These constants define the bit flags used in the LeaseSet2 flags field.
const (
	// LEASESET2_FLAG_OFFLINE_KEYS indicates that an offline signature is present (bit 0).
	// When set, the LeaseSet2Header contains an OfflineSignature structure.
	LEASESET2_FLAG_OFFLINE_KEYS = 1 << 0 // 0x0001

	// LEASESET2_FLAG_UNPUBLISHED indicates this is an unpublished leaseset (bit 1).
	// Unpublished leasesets should not be flooded, published, or sent in response to queries.
	// If expired, do not query the netdb for a new one unless FLAG_BLINDED is also set.
	LEASESET2_FLAG_UNPUBLISHED = 1 << 1 // 0x0002

	// LEASESET2_FLAG_BLINDED indicates this leaseset will be blinded and encrypted when published (bit 2).
	// If set, bit 1 (UNPUBLISHED) should also be set.
	// If this leaseset expires, query the blinded location in the netdb.
	// Introduced in I2P version 0.9.42.
	LEASESET2_FLAG_BLINDED = 1 << 2 // 0x0004
)

// LeaseSet2 Expiration Constants
// These constants define typical expiration time limits for LeaseSet2 structures.
const (
	// LEASESET2_MAX_EXPIRES_OFFSET is the maximum value that can be stored in the expires field (2 bytes).
	// This represents 65535 seconds or approximately 18.2 hours.
	LEASESET2_MAX_EXPIRES_OFFSET = 65535

	// LEASESET2_TYPICAL_MAX_EXPIRES is the typical maximum expiration offset for LeaseSet2 (660 seconds = 11 minutes).
	// While the field supports up to 18.2 hours, most implementations limit this to ~11 minutes.
	LEASESET2_TYPICAL_MAX_EXPIRES = 660

	// METALEASESET_MAX_EXPIRES is the maximum expiration offset for MetaLeaseSet (65535 seconds = 18.2 hours).
	// MetaLeaseSet can use the full range of the expires field.
	METALEASESET_MAX_EXPIRES = 65535
)
