// Package signature implements the I2P Signature common data structure
package signature

import (
	"github.com/samber/oops"
)

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
	// Determine signature length based on algorithm type
	// Each signature algorithm has a fixed-length output that must be validated
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

	// Validate that input data contains enough bytes for the signature
	// This prevents buffer overflow and ensures data integrity during parsing
	if len(data) < sigLength {
		err = oops.Errorf("insufficient data to read signature: need %d bytes, have %d", sigLength, len(data))
		log.WithError(err).Error("Failed to read Signature")
		return
	}
	
	// Extract signature bytes and prepare remainder for further processing
	// Creates a new Signature struct with validated data and type information
	sig = Signature{
		sigType: sigType,
		data:    data[:sigLength],
	}
	remainder = data[sigLength:]
	return
}
