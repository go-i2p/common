// Package key_certificate implements the I2P Destination common data structure
package key_certificate

import (
	"bytes"
	"encoding/binary"

	"github.com/go-i2p/crypto/types"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"

	"github.com/go-i2p/common/certificate"
)

// NewKeyCertificateWithTypes creates a key certificate with the specified signing and crypto key types.
// This is the recommended way to create key certificates.
//
// Parameters:
//   - signingType: The signing key type (e.g., KEYCERT_SIGN_ED25519)
//   - cryptoType: The crypto key type (e.g., KEYCERT_CRYPTO_X25519)
//
// Returns:
//   - *KeyCertificate: The newly created key certificate
//   - error: Any error encountered during creation
//
// Example:
//
//	keyCert, err := key_certificate.NewKeyCertificateWithTypes(
//	    key_certificate.KEYCERT_SIGN_ED25519,
//	    key_certificate.KEYCERT_CRYPTO_X25519,
//	)
func NewKeyCertificateWithTypes(signingType, cryptoType int) (*KeyCertificate, error) {
	log.WithFields(logger.Fields{
		"signing_type": signingType,
		"crypto_type":  cryptoType,
	}).Debug("Creating new key certificate with types")

	// Validate signing type
	if err := validateSigningType(signingType); err != nil {
		return nil, err
	}

	// Validate crypto type
	if err := validateCryptoType(cryptoType); err != nil {
		return nil, err
	}

	// Build the payload: 2 bytes for signing key type + 2 bytes for crypto key type
	payload := buildKeyCertificatePayload(signingType, cryptoType)

	// Create certificate with key certificate type
	cert, err := certificate.NewCertificateWithType(certificate.CERT_KEY, payload)
	if err != nil {
		return nil, oops.Errorf("failed to create certificate: %w", err)
	}

	// Convert to KeyCertificate
	keyCert, err := KeyCertificateFromCertificate(cert)
	if err != nil {
		return nil, oops.Errorf("failed to create KeyCertificate: %w", err)
	}

	log.WithFields(logger.Fields{
		"signing_type": signingType,
		"crypto_type":  cryptoType,
	}).Debug("Successfully created key certificate")

	return keyCert, nil
}

// buildKeyCertificatePayload constructs the minimal payload for a key certificate.
// The payload format is: [signing_type (2 bytes)] [crypto_type (2 bytes)] [excess signing key bytes] [excess crypto key bytes]
// For types where the key exceeds the standard KeysAndCert field size (KEYCERT_SPK_SIZE / KEYCERT_PUBKEY_SIZE),
// zero-filled placeholder bytes are appended for the excess material (e.g. P521 adds 4 bytes, RSA-2048 adds 128 bytes).
// Callers that have actual key material should populate those bytes after the fact.
func buildKeyCertificatePayload(signingType, cryptoType int) []byte {
	var payload bytes.Buffer

	// Write signing key type (2 bytes, big endian)
	signingBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(signingBytes, uint16(signingType))
	payload.Write(signingBytes)

	// Write crypto key type (2 bytes, big endian)
	cryptoBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(cryptoBytes, uint16(cryptoType))
	payload.Write(cryptoBytes)

	// For large signing keys (P521, RSA-2048/3072/4096): append zero-filled excess bytes.
	// Per I2P spec, excess signing key data beyond KEYCERT_SPK_SIZE (128 bytes) is stored
	// in the certificate payload immediately after the 4-byte type fields.
	if sigInfo, ok := SigningKeySizes[signingType]; ok && sigInfo.SigningPublicKeySize > KEYCERT_SPK_SIZE {
		excess := make([]byte, sigInfo.SigningPublicKeySize-KEYCERT_SPK_SIZE)
		payload.Write(excess)
	}

	// For large crypto keys (ECDH-P521): append zero-filled excess bytes.
	if crypInfo, ok := CryptoKeySizes[cryptoType]; ok && crypInfo.CryptoPublicKeySize > KEYCERT_PUBKEY_SIZE {
		excess := make([]byte, crypInfo.CryptoPublicKeySize-KEYCERT_PUBKEY_SIZE)
		payload.Write(excess)
	}

	return payload.Bytes()
}

// validateSigningType validates that the signing type is a known value.
// It derives validity from the authoritative SigningKeySizes map to prevent
// silent drift between the two registries.
func validateSigningType(signingType int) error {
	// Allow experimental range
	if signingType >= KEYCERT_SIGN_EXPERIMENTAL_START && signingType <= KEYCERT_SIGN_EXPERIMENTAL_END {
		return nil
	}

	// Use the authoritative SigningKeySizes map to avoid duplicate, drifting registries.
	if _, ok := SigningKeySizes[signingType]; !ok {
		return oops.Errorf("invalid signing key type: %d", signingType)
	}

	return nil
}

// validateCryptoType validates that the crypto type is a known value.
// It derives validity from the authoritative CryptoKeySizes map to prevent
// silent drift between the two registries.
func validateCryptoType(cryptoType int) error {
	// Check for spec-reserved type with specific error
	if cryptoType == KEYCERT_CRYPTO_RESERVED_NONE {
		return oops.Errorf("reserved crypto key type: RESERVED_NONE (type %d) is not implemented", cryptoType)
	}

	// Allow experimental range
	if cryptoType >= KEYCERT_CRYPTO_EXPERIMENTAL_START && cryptoType <= KEYCERT_CRYPTO_EXPERIMENTAL_END {
		return nil
	}

	// Use the authoritative CryptoKeySizes map to avoid duplicate, drifting registries.
	if _, ok := CryptoKeySizes[cryptoType]; !ok {
		return oops.Errorf("invalid crypto key type: %d", cryptoType)
	}

	return nil
}

// NewEd25519X25519KeyCertificate creates a key certificate with Ed25519 signing and X25519 crypto keys.
// This is the recommended key type combination for modern I2P applications.
//
// Ed25519 provides:
//   - High-performance signature verification
//   - 32-byte compact public keys
//   - 64-byte signatures
//   - 128-bit security level
//
// X25519 provides:
//   - High-performance key exchange
//   - 32-byte compact public keys
//   - 128-bit security level
//
// This combination is the current standard for router identities and destinations since I2P 0.9.15.
func NewEd25519X25519KeyCertificate() (*KeyCertificate, error) {
	return NewKeyCertificateWithTypes(KEYCERT_SIGN_ED25519, KEYCERT_CRYPTO_X25519)
}

// NewECDSAP256KeyCertificate creates a key certificate with ECDSA P-256 signing and ElGamal crypto keys.
// This combination provides 128-bit security level.
//
// DEPRECATED: Use NewEd25519X25519KeyCertificate for better performance.
// This is maintained for compatibility with legacy destinations.
func NewECDSAP256KeyCertificate() (*KeyCertificate, error) {
	return NewKeyCertificateWithTypes(KEYCERT_SIGN_P256, KEYCERT_CRYPTO_ELG)
}

// NewECDSAP384KeyCertificate creates a key certificate with ECDSA P-384 signing and ElGamal crypto keys.
// This combination provides 192-bit security level.
//
// DEPRECATED: Use NewEd25519X25519KeyCertificate for better performance.
// This is maintained for compatibility with legacy destinations.
func NewECDSAP384KeyCertificate() (*KeyCertificate, error) {
	return NewKeyCertificateWithTypes(KEYCERT_SIGN_P384, KEYCERT_CRYPTO_ELG)
}

// NewDSAElGamalKeyCertificate creates a key certificate with DSA-SHA1 signing and ElGamal crypto keys.
// This is the legacy key type combination from early I2P implementations.
//
// DEPRECATED: This algorithm is deprecated as of I2P 0.9.58.
// Use NewEd25519X25519KeyCertificate for new implementations.
// SHA-1 is cryptographically weak and DSA keys provide insufficient security.
// Maintained only for backward compatibility with legacy destinations.
func NewDSAElGamalKeyCertificate() (*KeyCertificate, error) {
	log.WithFields(logger.Fields{
		"algorithm": "DSA/ElGamal",
		"status":    "deprecated",
	}).Warn("DSA/ElGamal is deprecated as of I2P 0.9.58. Use Ed25519/X25519 instead for new implementations.")
	return NewKeyCertificateWithTypes(KEYCERT_SIGN_DSA_SHA1, KEYCERT_CRYPTO_ELG)
}

// NewRedDSAX25519KeyCertificate creates a key certificate with RedDSA-Ed25519 signing and X25519 crypto keys.
// RedDSA (randomized EdDSA) provides enhanced security over standard Ed25519.
//
// Supported for Destinations and EncryptedLeaseSets only, not Router Identities.
// Added in I2P specification 0.9.39.
func NewRedDSAX25519KeyCertificate() (*KeyCertificate, error) {
	return NewKeyCertificateWithTypes(KEYCERT_SIGN_REDDSA_ED25519, KEYCERT_CRYPTO_X25519)
}

// ConstructSigningPublicKeyByType constructs a SigningPublicKey from raw bytes and a
// signature type identifier. This is useful when creating a verifier for an offline
// transient signing key whose type may differ from the destination's key certificate.
//
// Parameters:
//   - data: Raw public key bytes (length must match expected size for sigType)
//   - sigType: Signature type identifier (e.g., KEYCERT_SIGN_ED25519)
//
// Returns the constructed SigningPublicKey or an error if the type is unsupported.
func ConstructSigningPublicKeyByType(data []byte, sigType int) (types.SigningPublicKey, error) {
	return selectSigningKeyConstructor(sigType, data)
}
