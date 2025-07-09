// Package certificate implements the certificate common-structure of I2P.
package certificate

// Certificate Types
const (
	CERT_NULL = iota
	CERT_HASHCASH
	CERT_HIDDEN
	CERT_SIGNED
	CERT_MULTIPLE
	CERT_KEY
)

// CERT_MIN_SIZE is the minimum size of a valid Certificate in []byte
// 1 byte for type
// 2 bytes for payload length
const CERT_MIN_SIZE = 3
