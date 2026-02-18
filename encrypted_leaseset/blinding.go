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
	// Validate signature type — Ed25519 (type 7) and RedDSA_SHA512_Ed25519 (type 11) supported.
	// Per I2P spec, RedDSA type 11 is defined "For Destinations and encrypted leasesets only."
	sigType := dest.KeyCertificate.SigningPublicKeyType()
	if sigType != key_certificate.KEYCERT_SIGN_ED25519 &&
		sigType != key_certificate.KEYCERT_SIGN_REDDSA_ED25519 {
		return destination.Destination{},
			oops.Wrapf(ErrUnsupportedSignatureType,
				"destination uses signature type %d, only Ed25519 (7) and RedDSA (11) supported for blinding",
				sigType)
	}

	// Format date as YYYY-MM-DD for blinding factor derivation
	dateStr := date.UTC().Format("2006-01-02")

	// Derive blinding factor from secret and date
	alpha, err := kdf.DeriveBlindingFactor(secret, dateStr)
	if err != nil {
		return destination.Destination{},
			oops.Wrapf(ErrInvalidSecret, "failed to derive blinding factor: %w", err)
	}

	// Get the original Ed25519 signing public key (32 bytes)
	originalSigningKey, err := dest.SigningPublicKey()
	if err != nil {
		return destination.Destination{},
			oops.Wrapf(ErrBlindingFailed, "failed to get signing public key: %w", err)
	}

	// Verify we have exactly 32 bytes for Ed25519
	if originalSigningKey.Len() != 32 {
		return destination.Destination{},
			oops.Wrapf(ErrBlindingFailed,
				"Ed25519 public key has wrong length: got %d, expected 32",
				originalSigningKey.Len())
	}

	// Convert to [32]byte array for blinding operation
	var pubKey [32]byte
	copy(pubKey[:], originalSigningKey.Bytes())

	// Blind the public key: P' = P + [alpha]B
	blindedPubKey, err := ed25519.BlindPublicKey(pubKey, alpha)
	if err != nil {
		return destination.Destination{},
			oops.Wrapf(ErrBlindingFailed, "failed to blind public key: %w", err)
	}

	// Create new Ed25519 signing public key from blinded bytes
	blindedSigningKey, err := ed25519.NewEd25519PublicKey(blindedPubKey[:])
	if err != nil {
		return destination.Destination{},
			oops.Wrapf(ErrBlindingFailed, "failed to create blinded signing key: %w", err)
	}

	// Create new KeysAndCert with the blinded signing key, keeping the same
	// encryption key, padding, and key certificate
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

	// Wrap in Destination
	blindedDest := destination.Destination{
		KeysAndCert: blindedKeysAndCert,
	}

	return blindedDest, nil
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
