// Package signature implements the I2P Signature common data structure
package signature

import (
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
	"github.com/sirupsen/logrus"
)

var log = logger.GetGoI2PLogger()

// Lengths of signature keys
const (
	DSA_SHA1_SIZE               = 40
	ECDSA_SHA256_P256_SIZE      = 64
	ECDSA_SHA384_P384_SIZE      = 96
	ECDSA_SHA512_P512_SIZE      = 132
	RSA_SHA256_2048_SIZE        = 256
	RSA_SHA384_3072_SIZE        = 384
	RSA_SHA512_4096_SIZE        = 512
	EdDSA_SHA512_Ed25519_SIZE   = 64
	EdDSA_SHA512_Ed25519ph_SIZE = 64
	RedDSA_SHA512_Ed25519_SIZE  = 64
)

const (
	SIGNATURE_TYPE_DSA_SHA1               = 0
	SIGNATURE_TYPE_ECDSA_SHA256_P256      = 1
	SIGNATURE_TYPE_ECDSA_SHA384_P384      = 2
	SIGNATURE_TYPE_ECDSA_SHA512_P521      = 3
	SIGNATURE_TYPE_RSA_SHA256_2048        = 4
	SIGNATURE_TYPE_RSA_SHA384_3072        = 5
	SIGNATURE_TYPE_RSA_SHA512_4096        = 6
	SIGNATURE_TYPE_EDDSA_SHA512_ED25519   = 7
	SIGNATURE_TYPE_EDDSA_SHA512_ED25519PH = 8
	SIGNATURE_TYPE_REDDSA_SHA512_ED25519  = 11
)

/*
[Signature]
Accurate for version 0.9.49

Description
This structure represents the signature of some data.

Contents
Signature type and length are inferred from the type of key used. The default type is
DSA_SHA1. As of release 0.9.12, other types may be supported, depending on context.
*/

// Signature is the represenation of an I2P Signature.
//
// https://geti2p.net/spec/common-structures#signature
type Signature []byte

// ReadSignature returns a Signature from a []byte.
// The remaining bytes after the specified length are also returned.
// Returns an error if there is insufficient data to read the signature.
//
// Since the signature type and length are inferred from context (the type of key used),
// and are not explicitly stated, this function assumes the default signature type (DSA_SHA1)
// with a length of 40 bytes.
//
// If a different signature type is expected based on context, this function should be
// modified accordingly to handle the correct signature length.
func ReadSignature(data []byte, sigType int) (sig Signature, remainder []byte, err error) {
	var sigLength int
	switch sigType {
	case SIGNATURE_TYPE_DSA_SHA1:
		sigLength = DSA_SHA1_SIZE
	case SIGNATURE_TYPE_ECDSA_SHA256_P256:
		sigLength = ECDSA_SHA256_P256_SIZE
	case SIGNATURE_TYPE_ECDSA_SHA384_P384:
		sigLength = ECDSA_SHA384_P384_SIZE
	case SIGNATURE_TYPE_ECDSA_SHA512_P521:
		sigLength = ECDSA_SHA512_P512_SIZE
	case SIGNATURE_TYPE_RSA_SHA256_2048:
		sigLength = RSA_SHA256_2048_SIZE
	case SIGNATURE_TYPE_RSA_SHA384_3072:
		sigLength = RSA_SHA384_3072_SIZE
	case SIGNATURE_TYPE_RSA_SHA512_4096:
		sigLength = RSA_SHA512_4096_SIZE
	case SIGNATURE_TYPE_EDDSA_SHA512_ED25519:
		sigLength = EdDSA_SHA512_Ed25519_SIZE
	case SIGNATURE_TYPE_EDDSA_SHA512_ED25519PH:
		sigLength = EdDSA_SHA512_Ed25519ph_SIZE
	case SIGNATURE_TYPE_REDDSA_SHA512_ED25519:
		sigLength = RedDSA_SHA512_Ed25519_SIZE
	default:
		err = oops.Errorf("unsupported signature type: %d", sigType)
		return
	}

	if len(data) < sigLength {
		err = oops.Errorf("insufficient data to read signature: need %d bytes, have %d", sigLength, len(data))
		log.WithError(err).Error("Failed to read Signature")
		return
	}
	sig = data[:sigLength]
	remainder = data[sigLength:]
	return
}

// NewSignature creates a new *Signature from []byte using ReadSignature.
// Returns a pointer to Signature unlike ReadSignature.
func NewSignature(data []byte, sigType int) (signature *Signature, remainder []byte, err error) {
	log.WithField("input_length", len(data)).Debug("Creating new Signature")
	sig, remainder, err := ReadSignature(data, sigType)
	if err != nil {
		log.WithError(err).Error("Failed to read Signature")
		return nil, remainder, err
	}
	signature = &sig
	log.WithFields(logrus.Fields{
		"signature_length": len(sig),
		"remainder_length": len(remainder),
	}).Debug("Successfully created new Signature")
	return
}
