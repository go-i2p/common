// Package key_certificate implements the I2P Destination common data structure
package key_certificate

import (
	"github.com/go-i2p/logger"
)

// log is the logger instance for the key_certificate package
var log = logger.GetGoI2PLogger()

// CryptoPublicKeySizes maps crypto key types to their sizes
var CryptoPublicKeySizes = map[uint16]int{
	CRYPTO_KEY_TYPE_ELGAMAL: 256,
}

// SignaturePublicKeySizes maps signature types to their sizes
var SignaturePublicKeySizes = map[uint16]int{
	SIGNATURE_TYPE_DSA_SHA1:       128,
	SIGNATURE_TYPE_ED25519_SHA512: 32,
}
