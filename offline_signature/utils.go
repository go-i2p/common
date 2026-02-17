// Package offline_signature implements the I2P OfflineSignature common data structure.
package offline_signature

import (
	"github.com/go-i2p/common/key_certificate"
	"github.com/go-i2p/common/signature"
)

// SigningPublicKeySize returns the byte length of a signing public key for the given signature type.
// This function maps I2P signature type identifiers to their corresponding public key sizes.
// Returns 0 for unknown or unsupported signature types.
//
// Signature types map to signing public key sizes as defined in I2P specification 0.9.67.
// Reference: https://geti2p.net/spec/common-structures#signingpublickey
func SigningPublicKeySize(sigtype uint16) int {
	switch sigtype {
	case key_certificate.KEYCERT_SIGN_DSA_SHA1:
		return key_certificate.KEYCERT_SIGN_DSA_SHA1_SIZE
	case key_certificate.KEYCERT_SIGN_P256:
		return key_certificate.KEYCERT_SIGN_P256_SIZE
	case key_certificate.KEYCERT_SIGN_P384:
		return key_certificate.KEYCERT_SIGN_P384_SIZE
	case key_certificate.KEYCERT_SIGN_P521:
		return key_certificate.KEYCERT_SIGN_P521_SIZE
	case key_certificate.KEYCERT_SIGN_RSA2048:
		return key_certificate.KEYCERT_SIGN_RSA2048_SIZE
	case key_certificate.KEYCERT_SIGN_RSA3072:
		return key_certificate.KEYCERT_SIGN_RSA3072_SIZE
	case key_certificate.KEYCERT_SIGN_RSA4096:
		return key_certificate.KEYCERT_SIGN_RSA4096_SIZE
	case key_certificate.KEYCERT_SIGN_ED25519:
		return key_certificate.KEYCERT_SIGN_ED25519_SIZE
	case key_certificate.KEYCERT_SIGN_ED25519PH:
		return key_certificate.KEYCERT_SIGN_ED25519PH_SIZE
	case key_certificate.KEYCERT_SIGN_REDDSA_ED25519:
		return key_certificate.KEYCERT_SIGN_ED25519_SIZE // RedDSA uses same size as Ed25519
	default:
		return 0 // Unknown or unsupported signature type
	}
}

// SignatureSize returns the byte length of a signature for the given signature type.
// This function maps I2P signature type identifiers to their corresponding signature sizes.
// Returns 0 for unknown or unsupported signature types.
//
// Signature sizes are defined in I2P specification 0.9.67.
// Reference: https://geti2p.net/spec/common-structures#signature
func SignatureSize(sigtype uint16) int {
	switch sigtype {
	case signature.SIGNATURE_TYPE_DSA_SHA1:
		return signature.DSA_SHA1_SIZE
	case signature.SIGNATURE_TYPE_ECDSA_SHA256_P256:
		return signature.ECDSA_SHA256_P256_SIZE
	case signature.SIGNATURE_TYPE_ECDSA_SHA384_P384:
		return signature.ECDSA_SHA384_P384_SIZE
	case signature.SIGNATURE_TYPE_ECDSA_SHA512_P521:
		return signature.ECDSA_SHA512_P521_SIZE
	case signature.SIGNATURE_TYPE_RSA_SHA256_2048:
		return signature.RSA_SHA256_2048_SIZE
	case signature.SIGNATURE_TYPE_RSA_SHA384_3072:
		return signature.RSA_SHA384_3072_SIZE
	case signature.SIGNATURE_TYPE_RSA_SHA512_4096:
		return signature.RSA_SHA512_4096_SIZE
	case signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519:
		return signature.EdDSA_SHA512_Ed25519_SIZE
	case signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519PH:
		return signature.EdDSA_SHA512_Ed25519ph_SIZE
	case signature.SIGNATURE_TYPE_REDDSA_SHA512_ED25519:
		return signature.RedDSA_SHA512_Ed25519_SIZE
	default:
		return 0 // Unknown or unsupported signature type
	}
}
