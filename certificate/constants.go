// Package certificate implements the certificate common-structure of I2P.
package certificate

// Certificate Types
const ( //nolint:golint
	CERT_NULL     = iota //nolint:golint
	CERT_HASHCASH        //nolint:golint
	CERT_HIDDEN          //nolint:golint
	CERT_SIGNED          //nolint:golint
	CERT_MULTIPLE        //nolint:golint
	CERT_KEY             //nolint:golint
)

// CERT_MIN_SIZE is the minimum size of a valid Certificate in []byte
// 1 byte for type
// 2 bytes for payload length
const CERT_MIN_SIZE = 3

// ============ Certificate Field Offsets ============

// CERT_TYPE_FIELD_END is the end index for the certificate type field (1 byte)
const CERT_TYPE_FIELD_END = 1

// CERT_LENGTH_FIELD_START is the start index for the certificate length field
const CERT_LENGTH_FIELD_START = 1

// CERT_LENGTH_FIELD_END is the end index for the certificate length field (2 bytes total)
const CERT_LENGTH_FIELD_END = 3

// CERT_SIGNING_KEY_TYPE_SIZE is the size in bytes of the signing key type field in key certificates
const CERT_SIGNING_KEY_TYPE_SIZE = 2 //nolint:golint

// ============ Certificate Validation Limits ============

// CERT_MAX_PAYLOAD_SIZE is the maximum allowed size for certificate payload
// according to I2P specification (2 bytes can represent up to 65535)
const CERT_MAX_PAYLOAD_SIZE = 65535

// CERT_MAX_TYPE_VALUE is the maximum valid certificate type value
// that fits in a single byte (0-255 range)
const CERT_MAX_TYPE_VALUE = 255

// CERT_MIN_KEY_PAYLOAD_SIZE is the minimum payload size required for KEY certificates
// to contain the signature type field (2 bytes minimum)
const CERT_MIN_KEY_PAYLOAD_SIZE = 4

// ============ Certificate Data Extraction ============

// CERT_KEY_SIG_TYPE_OFFSET is the byte offset where signature type begins in KEY certificate payload
const CERT_KEY_SIG_TYPE_OFFSET = 0

// CERT_KEY_CRYPTO_TYPE_OFFSET is the byte offset where crypto key type begins in KEY certificate payload
const CERT_KEY_CRYPTO_TYPE_OFFSET = 2

// CERT_CRYPTO_KEY_TYPE_SIZE is the size in bytes of the crypto key type field in key certificates
const CERT_CRYPTO_KEY_TYPE_SIZE = 2

// ============ Certificate Creation Defaults ============

// CERT_DEFAULT_TYPE_SIZE is the size in bytes for the certificate type field
const CERT_DEFAULT_TYPE_SIZE = 1

// CERT_LENGTH_FIELD_SIZE is the size in bytes for the certificate length field
const CERT_LENGTH_FIELD_SIZE = 2

// CERT_EMPTY_PAYLOAD_SIZE represents the size of an empty payload
const CERT_EMPTY_PAYLOAD_SIZE = 0

// CERT_SIGNED_PAYLOAD_SHORT is the spec-defined SIGNED certificate payload length
// containing a 40-byte DSA signature only.
const CERT_SIGNED_PAYLOAD_SHORT = 40

// CERT_SIGNED_PAYLOAD_LONG is the spec-defined SIGNED certificate payload length
// containing a 40-byte DSA signature followed by a 32-byte Hash of the signing Destination.
const CERT_SIGNED_PAYLOAD_LONG = 72
