package encrypted_leaseset

import (
	"time"

	"github.com/go-i2p/common/destination"
	"github.com/go-i2p/common/key_certificate"
	"github.com/go-i2p/common/keys_and_cert"
	"github.com/go-i2p/crypto/ed25519"
	"github.com/go-i2p/crypto/kdf"
	"github.com/samber/oops"
)

var (
	// ErrUnsupportedSignatureType indicates the destination signature type is not supported for blinding
	ErrUnsupportedSignatureType = oops.Errorf("signature type not supported for blinding (only Ed25519 supported)")

	// ErrInvalidSecret indicates the secret is invalid for blinding
	ErrInvalidSecret = oops.Errorf("invalid secret for blinding")

	// ErrBlindingFailed indicates the blinding operation failed
	ErrBlindingFailed = oops.Errorf("blinding operation failed")
)

// CreateBlindedDestination creates a blinded destination from an original destination,
// secret, and date. This is the core operation for EncryptedLeaseSet privacy.
//
// The blinding process:
//  1. Derives blinding factor (alpha) from secret and date using HKDF
//  2. Blinds the Ed25519 signing public key: P' = P + [alpha]B
//  3. Constructs a new destination with the blinded signing key
//
// The blinded destination is deterministic (same secret + date = same blinded dest)
// and unlinkable to the original destination without knowing the secret.
//
// Parameters:
//   - dest: Original destination to blind (must use Ed25519 signature type)
//   - secret: 32+ byte secret (typically from the destination's private key seed)
//   - date: Date for which to create the blinded destination (rotation period)
//
// Returns:
//   - Blinded destination with same key certificate but blinded signing key
//   - Error if signature type unsupported, secret invalid, or blinding fails
//
// Example:
//
//	// Create blinded destination for today
//	blindedDest, err := CreateBlindedDestination(originalDest, privateKeySeed, time.Now())
//	if err != nil {
//	    return err
//	}
//
// Security Notes:
//   - The secret MUST be kept confidential (compromise reveals original destination)
//   - Blinded destinations rotate daily (use same secret, different dates)
//   - Only Ed25519 signature types are supported (RedDSA SHA512 Ed25519)
//
// Spec: I2P Proposal 123 - Encrypted LeaseSet
func CreateBlindedDestination(dest destination.Destination, secret []byte, date time.Time) (destination.Destination, error) {
	if err := validateBlindingSigType(dest); err != nil {
		return destination.Destination{}, err
	}

	blindedPubKey, err := deriveBlindedPublicKey(dest, secret, date)
	if err != nil {
		return destination.Destination{}, err
	}

	return assembleBlindedDestination(dest, blindedPubKey)
}

// validateBlindingSigType checks that the destination uses an Ed25519-compatible
// signature type suitable for blinding operations.
func validateBlindingSigType(dest destination.Destination) error {
	sigType := dest.KeyCertificate.SigningPublicKeyType()
	if sigType != key_certificate.KEYCERT_SIGN_ED25519 &&
		sigType != key_certificate.KEYCERT_SIGN_REDDSA_ED25519 {
		return oops.Wrapf(ErrUnsupportedSignatureType,
			"destination uses signature type %d, only Ed25519 (7) and RedDSA (11) supported for blinding",
			sigType)
	}
	return nil
}

// deriveBlindedPublicKey derives the blinding factor from the secret and date,
// extracts the original signing key, and computes the blinded public key.
func deriveBlindedPublicKey(dest destination.Destination, secret []byte, date time.Time) ([32]byte, error) {
	dateStr := date.UTC().Format("2006-01-02")

	alpha, err := kdf.DeriveBlindingFactor(secret, dateStr)
	if err != nil {
		return [32]byte{}, oops.Wrapf(ErrInvalidSecret, "failed to derive blinding factor: %w", err)
	}

	pubKey, err := extractOriginalSigningKey(dest)
	if err != nil {
		return [32]byte{}, err
	}

	blindedPubKey, err := ed25519.BlindPublicKey(pubKey, alpha)
	if err != nil {
		return [32]byte{}, oops.Wrapf(ErrBlindingFailed, "failed to blind public key: %w", err)
	}

	return blindedPubKey, nil
}

// extractOriginalSigningKey retrieves and validates the 32-byte Ed25519 signing
// public key from a destination.
func extractOriginalSigningKey(dest destination.Destination) ([32]byte, error) {
	originalSigningKey, err := dest.SigningPublicKey()
	if err != nil {
		return [32]byte{}, oops.Wrapf(ErrBlindingFailed, "failed to get signing public key: %w", err)
	}

	if originalSigningKey.Len() != 32 {
		return [32]byte{}, oops.Wrapf(ErrBlindingFailed,
			"Ed25519 public key has wrong length: got %d, expected 32",
			originalSigningKey.Len())
	}

	var pubKey [32]byte
	copy(pubKey[:], originalSigningKey.Bytes())
	return pubKey, nil
}

// assembleBlindedDestination constructs a new destination with the blinded signing
// key, preserving the original encryption key, padding, and key certificate.
func assembleBlindedDestination(dest destination.Destination, blindedPubKey [32]byte) (destination.Destination, error) {
	blindedSigningKey, err := ed25519.NewEd25519PublicKey(blindedPubKey[:])
	if err != nil {
		return destination.Destination{},
			oops.Wrapf(ErrBlindingFailed, "failed to create blinded signing key: %w", err)
	}

	blindedKeysAndCert, err := keys_and_cert.NewKeysAndCert(
		dest.KeyCertificate,
		dest.ReceivingPublic,
		dest.Padding,
		blindedSigningKey,
	)
	if err != nil {
		return destination.Destination{},
			oops.Wrapf(ErrBlindingFailed, "failed to construct blinded keys and cert: %w", err)
	}

	return destination.Destination{KeysAndCert: blindedKeysAndCert}, nil
}

// VerifyBlindedSignature verifies that a blinded destination was correctly derived
// from an original destination using the given blinding factor.
//
// This verification checks: BlindedPubKey = OriginalPubKey + [alpha]B
//
// Parameters:
//   - blinded: The blinded destination to verify
//   - original: The original destination
//   - alpha: The blinding factor used (32 bytes)
//
// Returns:
//   - true if blinded destination matches the expected blinding of original
//   - false if verification fails or destinations don't match
//
// Example:
//
//	// Verify blinded destination was created correctly
//	alpha, _ := kdf.DeriveBlindingFactor(secret, "2025-11-24")
//	if !VerifyBlindedSignature(blindedDest, originalDest, alpha) {
//	    return errors.New("blinded destination verification failed")
//	}
//
// Spec: I2P Proposal 123 - Encrypted LeaseSet
func VerifyBlindedSignature(blinded, original destination.Destination, alpha [32]byte) bool {
	origPubKey, err := extractEd25519SigningKey(original)
	if err != nil {
		return false
	}

	blindedKeyBytes, err := extractEd25519SigningKey(blinded)
	if err != nil {
		return false
	}

	return compareBlindedKeys(origPubKey, blindedKeyBytes, alpha)
}

// extractEd25519SigningKey validates that the destination uses Ed25519 and returns
// the 32-byte signing public key.
func extractEd25519SigningKey(dest destination.Destination) ([32]byte, error) {
	var result [32]byte
	if dest.KeyCertificate.SigningPublicKeyType() != key_certificate.KEYCERT_SIGN_ED25519 {
		return result, oops.Errorf("destination does not use Ed25519")
	}
	key, err := dest.SigningPublicKey()
	if err != nil {
		return result, err
	}
	if key.Len() != 32 {
		return result, oops.Errorf("invalid Ed25519 key length: %d", key.Len())
	}
	copy(result[:], key.Bytes())
	return result, nil
}

// compareBlindedKeys computes the expected blinded key from the original key and alpha,
// then compares it against the actual blinded key bytes.
func compareBlindedKeys(origPubKey [32]byte, blindedPubKey [32]byte, alpha [32]byte) bool {
	expectedBlindedKey, err := ed25519.BlindPublicKey(origPubKey, alpha)
	if err != nil {
		return false
	}
	return expectedBlindedKey == blindedPubKey
}
