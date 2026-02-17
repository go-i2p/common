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
	KEYCERT_CRYPTO_ELG:              KEYCERT_CRYPTO_ELG_SIZE,
	KEYCERT_CRYPTO_P256:             KEYCERT_CRYPTO_P256_SIZE,
	KEYCERT_CRYPTO_P384:             KEYCERT_CRYPTO_P384_SIZE,
	KEYCERT_CRYPTO_P521:             KEYCERT_CRYPTO_P521_SIZE,
	KEYCERT_CRYPTO_X25519:           KEYCERT_CRYPTO_X25519_SIZE,
	KEYCERT_CRYPTO_MLKEM512_X25519:  KEYCERT_CRYPTO_MLKEM512_X25519_SIZE,
	KEYCERT_CRYPTO_MLKEM768_X25519:  KEYCERT_CRYPTO_MLKEM768_X25519_SIZE,
	KEYCERT_CRYPTO_MLKEM1024_X25519: KEYCERT_CRYPTO_MLKEM1024_X25519_SIZE,
}

// SignaturePublicKeySizes maps signature types to their public key sizes in bytes.
// This mapping is essential for parsing signing public keys from certificate data
// and ensuring that the correct amount of data is read for each signature algorithm.
// The sizes correspond to the public key portion used in signature verification.
var SignaturePublicKeySizes = map[uint16]int{
	KEYCERT_SIGN_DSA_SHA1:       KEYCERT_SIGN_DSA_SHA1_SIZE,
	KEYCERT_SIGN_P256:           KEYCERT_SIGN_P256_SIZE,
	KEYCERT_SIGN_P384:           KEYCERT_SIGN_P384_SIZE,
	KEYCERT_SIGN_P521:           KEYCERT_SIGN_P521_SIZE,
	KEYCERT_SIGN_RSA2048:        KEYCERT_SIGN_RSA2048_SIZE,
	KEYCERT_SIGN_RSA3072:        KEYCERT_SIGN_RSA3072_SIZE,
	KEYCERT_SIGN_RSA4096:        KEYCERT_SIGN_RSA4096_SIZE,
	KEYCERT_SIGN_ED25519:        KEYCERT_SIGN_ED25519_SIZE,
	KEYCERT_SIGN_ED25519PH:      KEYCERT_SIGN_ED25519PH_SIZE,
	KEYCERT_SIGN_REDDSA_ED25519: KEYCERT_SIGN_ED25519_SIZE, // RedDSA uses same key format as Ed25519
}
