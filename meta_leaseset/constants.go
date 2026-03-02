// Package meta_leaseset implements the I2P MetaLeaseSet common data structure
package meta_leaseset

// MetaLeaseSet Structure Size Constants
// These constants define the minimum and maximum sizes for MetaLeaseSet components
// according to I2P specification 0.9.67.
const (
	// META_LEASESET_TYPE is the Database Store type identifier for MetaLeaseSet.
	META_LEASESET_TYPE = 7

	// META_LEASESET_MIN_SIZE is the absolute minimum size for a MetaLeaseSet structure.
	// Destination (387) + published (4) + expires (2) + flags (2) + options (2) +
	// num (1) + 1 entry (40) + numr (1) + signature (64 bytes EdDSA)
	// = 387 + 4 + 2 + 2 + 2 + 1 + 40 + 1 + 64 = 503 bytes minimum
	META_LEASESET_MIN_SIZE = 503

	// META_LEASESET_HEADER_MIN_SIZE is the minimum size of MetaLeaseSet header without offline signature.
	// Destination (387 bytes) + published (4 bytes) + expires (2 bytes) + flags (2 bytes)
	// = 395 bytes
	META_LEASESET_HEADER_MIN_SIZE = 395

	// META_LEASESET_MIN_DESTINATION_SIZE is the minimum size for a valid I2P Destination.
	// This is 387 bytes: 384 bytes for KeysAndCert data + minimum 3 bytes for certificate.
	META_LEASESET_MIN_DESTINATION_SIZE = 387

	// META_LEASESET_PUBLISHED_SIZE is the size of the published timestamp field (4 bytes, seconds since epoch).
	META_LEASESET_PUBLISHED_SIZE = 4

	// META_LEASESET_EXPIRES_SIZE is the size of the expires offset field (2 bytes, offset from published in seconds).
	// MetaLeaseSet supports extended expiration up to 65535 seconds (18.2 hours).
	META_LEASESET_EXPIRES_SIZE = 2

	// META_LEASESET_FLAGS_SIZE is the size of the flags field (2 bytes).
	META_LEASESET_FLAGS_SIZE = 2

	// META_LEASESET_NUM_ENTRIES_SIZE is the size of the num_entries field (1 byte).
	META_LEASESET_NUM_ENTRIES_SIZE = 1

	// META_LEASESET_ENTRY_HASH_SIZE is the size of each entry's hash field (32 bytes, SHA256).
	META_LEASESET_ENTRY_HASH_SIZE = 32

	// META_LEASESET_ENTRY_FLAGS_SIZE is the size of each entry's flags field (3 bytes).
	// Bits 3-0 encode the entry type, bits 23-4 are reserved.
	META_LEASESET_ENTRY_FLAGS_SIZE = 3

	// META_LEASESET_ENTRY_COST_SIZE is the size of each entry's cost field (1 byte).
	META_LEASESET_ENTRY_COST_SIZE = 1

	// META_LEASESET_ENTRY_END_DATE_SIZE is the size of each entry's end_date field (4 bytes, seconds since epoch).
	META_LEASESET_ENTRY_END_DATE_SIZE = 4

	// META_LEASESET_ENTRY_SIZE is the fixed total size of a single MetaLease entry.
	// Per spec: hash (32) + flags (3) + cost (1) + end_date (4) = 40 bytes.
	META_LEASESET_ENTRY_SIZE = 40

	// META_LEASESET_NUM_REVOCATIONS_SIZE is the size of the numr field (1 byte).
	META_LEASESET_NUM_REVOCATIONS_SIZE = 1

	// META_LEASESET_REVOCATION_HASH_SIZE is the size of each revocation hash (32 bytes).
	META_LEASESET_REVOCATION_HASH_SIZE = 32
)

// MetaLeaseSet Entry Count Limits
// These constants define the valid range for the number of entries in a MetaLeaseSet.
const (
	// META_LEASESET_MIN_ENTRIES is the minimum number of entries required (1).
	// A MetaLeaseSet must reference at least one other lease set.
	META_LEASESET_MIN_ENTRIES = 1

	// META_LEASESET_MAX_ENTRIES is the maximum number of entries allowed (16).
	// This allows aggregation of up to 16 destinations for load balancing.
	META_LEASESET_MAX_ENTRIES = 16
)

// MetaLeaseSet Flags Constants
// These constants define the bit flags used in the MetaLeaseSet flags field.
// MetaLeaseSet reuses a subset of LeaseSet2 flags.
const (
	// META_LEASESET_FLAG_OFFLINE_KEYS indicates that an offline signature is present (bit 0).
	// When set, the MetaLeaseSet header contains an OfflineSignature structure.
	META_LEASESET_FLAG_OFFLINE_KEYS = 1 << 0 // 0x0001

	// META_LEASESET_FLAG_UNPUBLISHED indicates this is an unpublished meta leaseset (bit 1).
	// Unpublished meta leasesets should not be flooded, published, or sent in response to queries.
	META_LEASESET_FLAG_UNPUBLISHED = 1 << 1 // 0x0002

	// META_LEASESET_FLAG_BLINDED indicates that this is a blinded meta leaseset (bit 2).
	// Per the I2P LeaseSet2Header spec, bit 2 signals that the destination is blinded.
	// Consumers MUST check this flag before making routing or netdb storage decisions.
	META_LEASESET_FLAG_BLINDED = 1 << 2 // 0x0004
)

// MetaLeaseSet Expiration Constants
// These constants define expiration time limits for MetaLeaseSet structures.
const (
	// META_LEASESET_MAX_EXPIRES_OFFSET is the maximum value that can be stored in the expires field (2 bytes).
	// This represents 65535 seconds or approximately 18.2 hours.
	// MetaLeaseSet can use the full range unlike LeaseSet2 which is typically limited to 11 minutes.
	META_LEASESET_MAX_EXPIRES_OFFSET = 65535
)

// MetaLeaseSet Entry Type Constants
// These constants define the valid lease set types that can be referenced in MetaLeaseSet entries.
const (
	// META_LEASESET_ENTRY_TYPE_UNKNOWN represents an unknown lease set type (0).
	// Per spec: "0 = unknown" in MetaLease flags bits 3-0.
	META_LEASESET_ENTRY_TYPE_UNKNOWN = 0

	// META_LEASESET_ENTRY_TYPE_LEASESET represents a legacy LeaseSet (type 1 in flags bits 3-0).
	META_LEASESET_ENTRY_TYPE_LEASESET = 1

	// META_LEASESET_ENTRY_TYPE_LEASESET2 represents a LeaseSet2 (type 3 in flags bits 3-0).
	META_LEASESET_ENTRY_TYPE_LEASESET2 = 3

	// META_LEASESET_ENTRY_TYPE_META_LEASESET represents a MetaLeaseSet (type 5 in flags bits 3-0).
	// Note: This is the MetaLease entry type value, not the EncryptedLeaseSet database store type.
	META_LEASESET_ENTRY_TYPE_META_LEASESET = 5
)
