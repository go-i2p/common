// Package key_certificate implements the I2P KeyCertificate common data structure
package key_certificate

import (
	"github.com/go-i2p/logger"
)

// log is the logger instance for the key_certificate package
// This logger provides structured logging for key certificate operations
// including parsing, validation, and cryptographic key construction.
var log = logger.GetGoI2PLogger()

// CryptoPublicKeySizes maps crypto key types to their sizes in bytes.
// This map is derived from the canonical CryptoKeySizes map to avoid
// duplicate data and manual synchronization.
//
// Deprecated: Prefer CryptoKeySizes (map[int]KeySizeInfo) for complete
// key size information including private key sizes.
var CryptoPublicKeySizes map[uint16]int

// SignaturePublicKeySizes maps signature types to their public key sizes in bytes.
// This map is derived from the canonical SigningKeySizes map to avoid
// duplicate data and manual synchronization.
//
// Deprecated: Prefer SigningKeySizes (map[int]KeySizeInfo) for complete
// key size information including signature and private key sizes.
var SignaturePublicKeySizes map[uint16]int

func init() {
	CryptoPublicKeySizes = make(map[uint16]int, len(CryptoKeySizes))
	for typ, info := range CryptoKeySizes {
		CryptoPublicKeySizes[uint16(typ)] = info.CryptoPublicKeySize
	}
	SignaturePublicKeySizes = make(map[uint16]int, len(SigningKeySizes))
	for typ, info := range SigningKeySizes {
		SignaturePublicKeySizes[uint16(typ)] = info.SigningPublicKeySize
	}
}
