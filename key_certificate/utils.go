// Package key_certificate implements the I2P Destination common data structure
package key_certificate

import (
	"github.com/go-i2p/logger"
)

// log is the logger instance for the key_certificate package
// This logger provides structured logging for key certificate operations
// including parsing, validation, and cryptographic key construction.
var log = logger.GetGoI2PLogger()

// CryptoPublicKeySizes maps crypto key types to their sizes in bytes.
// This mapping is used to validate key sizes during certificate parsing
// and to allocate appropriate buffer space for different encryption algorithms.
// The map provides a lookup table for determining the expected size of public keys
// based on their cryptographic algorithm type identifier.
var CryptoPublicKeySizes = map[uint16]int{
	KEYCERT_CRYPTO_ELG: 256,
}

// SignaturePublicKeySizes maps signature types to their public key sizes in bytes.
// This mapping is essential for parsing signing public keys from certificate data
// and ensuring that the correct amount of data is read for each signature algorithm.
// The sizes correspond to the public key portion used in signature verification.
var SignaturePublicKeySizes = map[uint16]int{
	SIGNATURE_TYPE_DSA_SHA1:       128,
	SIGNATURE_TYPE_ED25519_SHA512: 32,
}
