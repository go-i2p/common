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

// SignatureSize returns the expected byte length for the given signature algorithm type.
// This is the exported single source of truth for signature type-to-size mapping.
// Returns an error if the signature type is unsupported, reserved, or out of the
// valid range (0-65535) defined by the I2P spec's 2-byte Integer.
func SignatureSize(sigType int) (int, error) {
	return getSignatureLength(sigType)
}

// getSignatureLength determines the signature length based on the algorithm type.
// Each signature algorithm has a fixed-length output that must be validated.
// Validates that sigType is within the spec-defined 2-byte Integer range (0-65535).
// Returns a distinct error for reserved-but-unimplemented types vs completely unknown types.
func getSignatureLength(sigType int) (int, error) {
	if sigType < 0 || sigType > 65535 {
		return 0, oops.Errorf("signature type %d out of valid range (0-65535)", sigType)
	}
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
	case SIGNATURE_TYPE_GOST_R3410_2012_512:
		return 0, oops.Errorf("reserved signature type %d (GOST R 34.10-2012-512, Proposal 134): not implemented", sigType)
	case SIGNATURE_TYPE_GOST_R3410_2012_1024:
		return 0, oops.Errorf("reserved signature type %d (GOST R 34.10-2012-1024, Proposal 134): not implemented", sigType)
	case SIGNATURE_TYPE_REDDSA_SHA512_ED25519:
		return RedDSA_SHA512_Ed25519_SIZE, nil
	default:
		if sigType >= SIGNATURE_TYPE_MLDSA_RESERVED_START && sigType <= SIGNATURE_TYPE_MLDSA_RESERVED_END {
			return 0, oops.Errorf("reserved signature type %d (MLDSA range 12-20, Proposal 169): not implemented", sigType)
		}
		if sigType >= SIGNATURE_TYPE_EXPERIMENTAL_START && sigType <= SIGNATURE_TYPE_EXPERIMENTAL_END {
			return 0, oops.Errorf("experimental signature type %d (range 65280-65534): not supported", sigType)
		}
		return 0, oops.Errorf("unknown signature type: %d", sigType)
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
