// Package key_certificate implements the I2P KeyCertificate common data structure
package key_certificate

import (
	"github.com/samber/oops"
)

// KeySizeInfo contains size information for cryptographic keys.
// All sizes are in bytes.
type KeySizeInfo struct {
	// SignatureSize is the size of signatures produced by this signing key type
	SignatureSize int

	// SigningPublicKeySize is the size of the signing public key
	SigningPublicKeySize int

	// SigningPrivateKeySize is the size of the signing private key
	SigningPrivateKeySize int

	// CryptoPublicKeySize is the size of the encryption public key
	CryptoPublicKeySize int

	// CryptoPrivateKeySize is the size of the encryption private key
	CryptoPrivateKeySize int
}

// SigningKeySizes maps signing key types to their size information.
// This provides compile-time constant lookups without requiring object creation.
//
// Sizes are based on I2P specification 0.9.67:
// https://geti2p.net/spec/common-structures#certificate
var SigningKeySizes = map[int]KeySizeInfo{
	KEYCERT_SIGN_DSA_SHA1: {
		SignatureSize:         40,
		SigningPublicKeySize:  128,
		SigningPrivateKeySize: 20,
	},
	KEYCERT_SIGN_P256: {
		SignatureSize:         64,
		SigningPublicKeySize:  64,
		SigningPrivateKeySize: 32,
	},
	KEYCERT_SIGN_P384: {
		SignatureSize:         96,
		SigningPublicKeySize:  96,
		SigningPrivateKeySize: 48,
	},
	KEYCERT_SIGN_P521: {
		SignatureSize:         132,
		SigningPublicKeySize:  132,
		SigningPrivateKeySize: 66,
	},
	KEYCERT_SIGN_RSA2048: {
		SignatureSize:         256,
		SigningPublicKeySize:  256,
		SigningPrivateKeySize: 512,
	},
	KEYCERT_SIGN_RSA3072: {
		SignatureSize:         384,
		SigningPublicKeySize:  384,
		SigningPrivateKeySize: 768,
	},
	KEYCERT_SIGN_RSA4096: {
		SignatureSize:         512,
		SigningPublicKeySize:  512,
		SigningPrivateKeySize: 1024,
	},
	KEYCERT_SIGN_ED25519: {
		SignatureSize:         64,
		SigningPublicKeySize:  32,
		SigningPrivateKeySize: 32,
	},
	KEYCERT_SIGN_ED25519PH: {
		SignatureSize:         64,
		SigningPublicKeySize:  32,
		SigningPrivateKeySize: 32,
	},
	KEYCERT_SIGN_REDDSA_ED25519: {
		SignatureSize:         64,
		SigningPublicKeySize:  32,
		SigningPrivateKeySize: 32,
	},
}

// CryptoKeySizes maps crypto key types to their size information.
// This provides compile-time constant lookups without requiring object creation.
//
// Sizes are based on I2P specification 0.9.67:
// https://geti2p.net/spec/common-structures#certificate
var CryptoKeySizes = map[int]KeySizeInfo{
	KEYCERT_CRYPTO_ELG: {
		CryptoPublicKeySize:  256,
		CryptoPrivateKeySize: 256,
	},
	KEYCERT_CRYPTO_P256: {
		CryptoPublicKeySize:  64,
		CryptoPrivateKeySize: 32,
	},
	KEYCERT_CRYPTO_P384: {
		CryptoPublicKeySize:  96,
		CryptoPrivateKeySize: 48,
	},
	KEYCERT_CRYPTO_P521: {
		CryptoPublicKeySize:  132,
		CryptoPrivateKeySize: 66,
	},
	KEYCERT_CRYPTO_X25519: {
		CryptoPublicKeySize:  32,
		CryptoPrivateKeySize: 32,
	},
	// For MLKEM+X25519 hybrid types the CryptoPublicKeySize field records only the
	// 32-byte X25519 component that fits in the standard KeysAndCert public key field.
	// The full hybrid key (MLKEM + X25519) is larger; use GetMLKEMHybridKeySize to
	// obtain the combined size for MLKEM key-material handling.
	KEYCERT_CRYPTO_MLKEM512_X25519: {
		CryptoPublicKeySize:  32, // X25519 component within KeysAndCert; full hybrid = 832 bytes
		CryptoPrivateKeySize: 32,
	},
	KEYCERT_CRYPTO_MLKEM768_X25519: {
		CryptoPublicKeySize:  32, // X25519 component within KeysAndCert; full hybrid = 1216 bytes
		CryptoPrivateKeySize: 32,
	},
	KEYCERT_CRYPTO_MLKEM1024_X25519: {
		CryptoPublicKeySize:  32, // X25519 component within KeysAndCert; full hybrid = 1600 bytes
		CryptoPrivateKeySize: 32,
	},
}

// MLKEM+X25519 hybrid public key total sizes (MLKEM component + 32-byte X25519 component).
// These sizes apply to the full hybrid key material used outside the standard KeysAndCert
// structure (e.g. in LeaseSet2 / EncryptedLeaseSet blocks).
// Source: I2P Proposal 169 (Post-Quantum Cryptography).
const (
	// MLKEM512_X25519_HYBRID_SIZE is the full MLKEM-512+X25519 public key size (800 + 32 bytes).
	MLKEM512_X25519_HYBRID_SIZE = 832
	// MLKEM768_X25519_HYBRID_SIZE is the full MLKEM-768+X25519 public key size (1184 + 32 bytes).
	MLKEM768_X25519_HYBRID_SIZE = 1216
	// MLKEM1024_X25519_HYBRID_SIZE is the full MLKEM-1024+X25519 public key size (1568 + 32 bytes).
	MLKEM1024_X25519_HYBRID_SIZE = 1600
)

// GetMLKEMHybridKeySize returns the total combined public key size (MLKEM + X25519)
// for the given MLKEM+X25519 hybrid crypto type.
//
// Unlike CryptoKeySizes[type].CryptoPublicKeySize (which returns 32 bytes – the X25519
// component stored in the fixed KeysAndCert public key field), this function returns the
// full hybrid size needed when allocating buffers for MLKEM key-encapsulation operations.
//
// Returns an error for any non-MLKEM crypto type.
func GetMLKEMHybridKeySize(cryptoType int) (int, error) {
	switch cryptoType {
	case KEYCERT_CRYPTO_MLKEM512_X25519:
		return MLKEM512_X25519_HYBRID_SIZE, nil
	case KEYCERT_CRYPTO_MLKEM768_X25519:
		return MLKEM768_X25519_HYBRID_SIZE, nil
	case KEYCERT_CRYPTO_MLKEM1024_X25519:
		return MLKEM1024_X25519_HYBRID_SIZE, nil
	default:
		return 0, oops.Errorf("crypto type %d is not an MLKEM+X25519 hybrid type", cryptoType)
	}
}

// Note: CryptoPublicKeySizes is defined in utils.go for backward compatibility.
// Use the CryptoKeySizes map above for complete key size information.

// GetKeySizes returns size information for the given signing and crypto key types
// without requiring object creation.
//
// This function is useful for calculating padding sizes, buffer allocations,
// and validating data lengths before constructing full key certificates.
//
// Parameters:
//   - signingType: The signing key type (e.g., KEYCERT_SIGN_ED25519)
//   - cryptoType: The crypto key type (e.g., KEYCERT_CRYPTO_X25519)
//
// Returns:
//   - KeySizeInfo: Combined size information for both key types
//   - error: Error if either key type is unknown
//
// Example:
//
//	sizes, err := key_certificate.GetKeySizes(
//	    key_certificate.KEYCERT_SIGN_ED25519,
//	    key_certificate.KEYCERT_CRYPTO_X25519,
//	)
//	if err != nil {
//	    return err
//	}
//	paddingSize := keys_and_cert.KEYS_AND_CERT_DATA_SIZE -
//	    (sizes.CryptoPublicKeySize + sizes.SigningPublicKeySize)
func GetKeySizes(signingType, cryptoType int) (KeySizeInfo, error) {
	signingInfo, signingExists := SigningKeySizes[signingType]
	if !signingExists {
		return KeySizeInfo{}, oops.Errorf("unknown signing key type: %d", signingType)
	}

	cryptoInfo, cryptoExists := CryptoKeySizes[cryptoType]
	if !cryptoExists {
		return KeySizeInfo{}, oops.Errorf("unknown crypto key type: %d", cryptoType)
	}

	// Combine the information from both maps
	return KeySizeInfo{
		SignatureSize:         signingInfo.SignatureSize,
		SigningPublicKeySize:  signingInfo.SigningPublicKeySize,
		SigningPrivateKeySize: signingInfo.SigningPrivateKeySize,
		CryptoPublicKeySize:   cryptoInfo.CryptoPublicKeySize,
		CryptoPrivateKeySize:  cryptoInfo.CryptoPrivateKeySize,
	}, nil
}

// GetSigningKeySize returns the signing public key size for the given signing type.
// Returns error if the signing type is unknown.
func GetSigningKeySize(signingType int) (int, error) {
	info, exists := SigningKeySizes[signingType]
	if !exists {
		return 0, oops.Errorf("unknown signing key type: %d", signingType)
	}
	return info.SigningPublicKeySize, nil
}

// GetCryptoKeySize returns the crypto public key size for the given crypto type.
// Returns error if the crypto type is unknown.
func GetCryptoKeySize(cryptoType int) (int, error) {
	info, exists := CryptoKeySizes[cryptoType]
	if !exists {
		return 0, oops.Errorf("unknown crypto key type: %d", cryptoType)
	}
	return info.CryptoPublicKeySize, nil
}

// GetSignatureSize returns the signature size for the given signing type.
// Returns error if the signing type is unknown.
func GetSignatureSize(signingType int) (int, error) {
	info, exists := SigningKeySizes[signingType]
	if !exists {
		return 0, oops.Errorf("unknown signing key type: %d", signingType)
	}
	return info.SignatureSize, nil
}
