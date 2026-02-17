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
	sigLength, err := getSignatureLength(sigType)
	if err != nil {
		return
	}

	if err = validateSignatureData(data, sigLength); err != nil {
		return
	}

	sig, remainder = extractSignatureData(data, sigType, sigLength)
	return
}

// getSignatureLength determines the signature length based on the algorithm type.
// Each signature algorithm has a fixed-length output that must be validated.
// Returns an error if the signature type is unsupported.
func getSignatureLength(sigType int) (int, error) {
	switch sigType {
	case SIGNATURE_TYPE_DSA_SHA1:
		return DSA_SHA1_SIZE, nil
	case SIGNATURE_TYPE_ECDSA_SHA256_P256:
		return ECDSA_SHA256_P256_SIZE, nil
	case SIGNATURE_TYPE_ECDSA_SHA384_P384:
		return ECDSA_SHA384_P384_SIZE, nil
	case SIGNATURE_TYPE_ECDSA_SHA512_P521:
		return ECDSA_SHA512_P521_SIZE, nil
	case SIGNATURE_TYPE_RSA_SHA256_2048:
		return RSA_SHA256_2048_SIZE, nil
	case SIGNATURE_TYPE_RSA_SHA384_3072:
		return RSA_SHA384_3072_SIZE, nil
	case SIGNATURE_TYPE_RSA_SHA512_4096:
		return RSA_SHA512_4096_SIZE, nil
	case SIGNATURE_TYPE_EDDSA_SHA512_ED25519:
		return EdDSA_SHA512_Ed25519_SIZE, nil
	case SIGNATURE_TYPE_EDDSA_SHA512_ED25519PH:
		return EdDSA_SHA512_Ed25519ph_SIZE, nil
	case SIGNATURE_TYPE_REDDSA_SHA512_ED25519:
		return RedDSA_SHA512_Ed25519_SIZE, nil
	default:
		return 0, oops.Errorf("unsupported signature type: %d", sigType)
	}
}

// validateSignatureData validates that input data contains enough bytes for the signature.
// This prevents buffer overflow and ensures data integrity during parsing.
func validateSignatureData(data []byte, sigLength int) error {
	if len(data) < sigLength {
		err := oops.Errorf("insufficient data to read signature: need %d bytes, have %d", sigLength, len(data))
		log.WithError(err).Error("Failed to read Signature")
		return err
	}
	return nil
}

// extractSignatureData extracts signature bytes and prepares remainder for further processing.
// Creates a new Signature struct with validated data and type information.
// Data is defensively copied to prevent aliasing of the caller's buffer.
func extractSignatureData(data []byte, sigType int, sigLength int) (Signature, []byte) {
	sigData := make([]byte, sigLength)
	copy(sigData, data[:sigLength])
	sig := Signature{
		sigType: sigType,
		data:    sigData,
	}
	remainder := data[sigLength:]
	return sig, remainder
}
