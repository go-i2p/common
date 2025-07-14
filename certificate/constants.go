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
