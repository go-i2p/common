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
	//
	// These are the high-level authorization types exposed by the API. They are
	// distinct from the on-the-wire Layer 1 flag byte, which encodes a per-client
	// bit (bit 0) and a 3-bit authentication scheme (bits 3-1). See authFlagByte
	// and parseAuthFlag in client_auth.go for the mapping.

	// ENCRYPTED_LEASESET_AUTH_TYPE_NONE indicates no per-client authorization (type 0).
	ENCRYPTED_LEASESET_AUTH_TYPE_NONE byte = 0

	// ENCRYPTED_LEASESET_AUTH_TYPE_DH indicates per-client DH (X25519) authorization (type 1).
	ENCRYPTED_LEASESET_AUTH_TYPE_DH byte = 1

	// ENCRYPTED_LEASESET_AUTH_TYPE_PSK indicates per-client PSK authorization (type 2).
	ENCRYPTED_LEASESET_AUTH_TYPE_PSK byte = 2

	// Layer 1 flag byte bit layout (per I2P encryptedleaseset spec §"Layer 1 (middle)").

	// ENCRYPTED_LEASESET_AUTH_FLAG_PERCLIENT is bit 0 of the Layer 1 flag byte:
	// 0 = data is for everybody (no per-client auth), 1 = per-client auth section follows.
	ENCRYPTED_LEASESET_AUTH_FLAG_PERCLIENT byte = 0x01

	// ENCRYPTED_LEASESET_AUTH_SCHEME_SHIFT is the bit offset of the auth scheme field (bits 3-1).
	ENCRYPTED_LEASESET_AUTH_SCHEME_SHIFT uint = 1

	// ENCRYPTED_LEASESET_AUTH_SCHEME_MASK masks the 3-bit auth scheme field after shifting.
	ENCRYPTED_LEASESET_AUTH_SCHEME_MASK byte = 0x07

	// ENCRYPTED_LEASESET_AUTH_SCHEME_DH is the wire scheme value for DH client auth (000).
	ENCRYPTED_LEASESET_AUTH_SCHEME_DH byte = 0

	// ENCRYPTED_LEASESET_AUTH_SCHEME_PSK is the wire scheme value for PSK client auth (001).
	ENCRYPTED_LEASESET_AUTH_SCHEME_PSK byte = 1

	// Per-client authorization field sizes.

	// ENCRYPTED_LEASESET_X25519_KEY_SIZE is the size of an X25519 public or private key (32 bytes).
	ENCRYPTED_LEASESET_X25519_KEY_SIZE int = 32

	// ENCRYPTED_LEASESET_PSK_SIZE is the size of a pre-shared key (32 bytes).
	ENCRYPTED_LEASESET_PSK_SIZE int = 32

	// ENCRYPTED_LEASESET_AUTH_COOKIE_SIZE is the size of the shared authCookie (32 bytes).
	ENCRYPTED_LEASESET_AUTH_COOKIE_SIZE int = 32

	// ENCRYPTED_LEASESET_AUTH_SALT_SIZE is the size of the PSK authSalt (32 bytes).
	ENCRYPTED_LEASESET_AUTH_SALT_SIZE int = 32

	// ENCRYPTED_LEASESET_CLIENT_ID_SIZE is the size of a per-client identifier (8 bytes).
	ENCRYPTED_LEASESET_CLIENT_ID_SIZE int = 8

	// ENCRYPTED_LEASESET_CLIENT_COOKIE_SIZE is the size of a per-client encrypted cookie (32 bytes).
	ENCRYPTED_LEASESET_CLIENT_COOKIE_SIZE int = 32

	// ENCRYPTED_LEASESET_AUTH_CLIENT_SIZE is the size of a single authClient entry:
	// clientID(8) + clientCookie(32) = 40 bytes.
	ENCRYPTED_LEASESET_AUTH_CLIENT_SIZE int = 40

	// ENCRYPTED_LEASESET_AUTH_CLIENT_COUNT_SIZE is the size of the client-count field (2 bytes, big endian).
	ENCRYPTED_LEASESET_AUTH_CLIENT_COUNT_SIZE int = 2

	// ENCRYPTED_LEASESET_AUTH_OKM_SIZE is the HKDF output length for per-client key
	// derivation: clientKey(32) + clientIV(12) + clientID(8) = 52 bytes.
	ENCRYPTED_LEASESET_AUTH_OKM_SIZE int = 52

	// ENCRYPTED_LEASESET_AUTH_MAX_CLIENTS bounds the number of authClient entries
	// accepted when parsing, to prevent unbounded allocation from malformed input.
	ENCRYPTED_LEASESET_AUTH_MAX_CLIENTS int = 65535
)

// HKDF info strings for per-client authorization key derivation.
const (
	// ELS2_DH_AUTH_INFO is the HKDF info string for DH client authorization ("ELS2_XCA").
	ELS2_DH_AUTH_INFO = "ELS2_XCA"

	// ELS2_PSK_AUTH_INFO is the HKDF info string for PSK client authorization ("ELS2PSKA").
	ELS2_PSK_AUTH_INFO = "ELS2PSKA"
)
