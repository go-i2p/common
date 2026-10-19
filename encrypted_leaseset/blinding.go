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
	ErrUnsupportedSignatureType = oops.Errorf("signature type not supported for blinding (only Ed25519 (7) and RedDSA (11) are supported)")

	// ErrInvalidSecret is retained for backward compatibility only.
	//
	// Deprecated: the I2P encrypted-leaseset specification treats the blinding
	// secret as an optional UTF-8 string ("secret is optional, else zero-length"),
	// so there is no minimum-length rule to violate. Blinding no longer validates
	// a secret length and this sentinel is never returned.
	ErrInvalidSecret = oops.Errorf("invalid secret for blinding")

	// ErrBlindingFailed indicates the blinding operation failed
	ErrBlindingFailed = oops.Errorf("blinding operation failed")
)

// CreateBlindedDestination creates a blinded destination from an original destination,
// secret, and date. This is the core operation for EncryptedLeaseSet privacy.
//
// The blinding process:
//  1. Derives the blinding factor (alpha) bound to the destination's signing
//     public key, its signature type, the date, and the optional secret
//  2. Blinds the Ed25519 signing public key: P' = P + [alpha]B
//  3. Constructs a new destination with the blinded signing key
//
// The blinded destination is deterministic (same destination + secret + date =
// same blinded dest) and unlinkable to the original destination without knowing
// the destination's signing public key.
//
// Parameters:
//   - dest: Original destination to blind (must use Ed25519 or RedDSA type)
//   - secret: optional UTF-8 secret for private links; may be empty. Per the
//     specification the secret is "UTF-8 encoded string ... else zero-length",
//     so there is no minimum length requirement.
//   - date: Date for which to create the blinded destination (rotation period)
//
// Returns:
//   - Blinded destination with same key certificate but blinded signing key
//   - Error if signature type unsupported or blinding fails
//
// Example:
//
//	// Create blinded destination for today, with no secret (public link)
//	blindedDest, err := CreateBlindedDestination(originalDest, nil, time.Now())
//	if err != nil {
//	    return err
//	}
//
// Security Notes:
//   - The secret MUST be kept confidential (compromise reveals original destination)
//   - Blinded destinations rotate daily (use same secret, different dates)
//   - Only Ed25519 (7) and RedDSA (11) signing types are supported
//   - alpha is bound to the destination's signing public key, so the same
//     secret+date yields a different alpha for each destination
//
// Spec: https://geti2p.net/spec/encryptedleaseset §"Blinding Calculations"
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
	if dest.KeysAndCert == nil || dest.KeyCertificate == nil {
		return oops.Wrapf(ErrUnsupportedSignatureType, "destination has nil KeysAndCert or KeyCertificate")
	}
	sigType := dest.KeyCertificate.SigningPublicKeyType()
	if sigType != key_certificate.KEYCERT_SIGN_ED25519 &&
		sigType != key_certificate.KEYCERT_SIGN_REDDSA_ED25519 {
		return oops.Wrapf(ErrUnsupportedSignatureType,
			"destination uses signature type %d, only Ed25519 (7) and RedDSA (11) supported for blinding",
			sigType)
	}
	return nil
}

// deriveBlindedPublicKey derives the spec-conformant blinding factor (alpha),
// extracts the original signing key, and computes the blinded public key.
//
// Per https://geti2p.net/spec/encryptedleaseset §"Blinding Calculations":
//
//	keydata = A || stA || stA'
//	seed    = HKDF(H("I2PGenerateAlpha", keydata), yyyyMMdd || secret, "i2pblinding1", 64)
//	alpha   = seed mod L
//
// kdf.DeriveBlindingFactorI2P implements exactly this construction, binding
// alpha to the destination signing public key A and both signature types. The
// blinded public key is then A' = A + [alpha]B (BLIND_PUBKEY).
func deriveBlindedPublicKey(dest destination.Destination, secret []byte, date time.Time) ([32]byte, error) {
	pubKey, err := extractOriginalSigningKey(dest)
	if err != nil {
		return [32]byte{}, err
	}

	sigType := uint16(dest.KeyCertificate.SigningPublicKeyType())
	alpha, err := kdf.DeriveBlindingFactorI2P(pubKey[:], string(secret), sigType, date)
	if err != nil {
		return [32]byte{}, oops.Wrapf(ErrBlindingFailed, "failed to derive blinding factor: %w", err)
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
// key, preserving the original encryption key and padding.
//
// The blinded destination's key certificate declares signing type RedDSA (11),
// NOT the original destination's type. Per the I2P encrypted-leaseset spec:
//
//	"Blinded Public Key Sig Type: 2 bytes, big endian. This will always be
//	 type 11, identifying a Red25519 blinded key."
//
// and, in the blinding calculations, "stA' = signature type of A', 2 bytes big
// endian (0x000b)". kdf.DeriveBlindingFactorI2P already mixes 0x000b into the
// alpha salt, so declaring anything else would make the emitted structure
// inconsistent with the key material it was derived from. The crypto type and
// the 32-byte key length are unchanged (Ed25519 and RedDSA are both 32 bytes).
func assembleBlindedDestination(dest destination.Destination, blindedPubKey [32]byte) (destination.Destination, error) {
	blindedSigningKey, err := ed25519.NewEd25519PublicKey(blindedPubKey[:])
	if err != nil {
		return destination.Destination{},
			oops.Wrapf(ErrBlindingFailed, "failed to create blinded signing key: %w", err)
	}

	blindedKeyCert, err := key_certificate.NewKeyCertificateWithTypes(
		key_certificate.KEYCERT_SIGN_REDDSA_ED25519,
		dest.KeyCertificate.PublicKeyType(),
	)
	if err != nil {
		return destination.Destination{},
			oops.Wrapf(ErrBlindingFailed, "failed to build blinded key certificate (RedDSA 11): %w", err)
	}

	blindedKeysAndCert, err := keys_and_cert.NewKeysAndCert(
		blindedKeyCert,
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
//	alpha, _ := kdf.DeriveBlindingFactorI2P(
//	    origPubKey, secretString,
//	    kdf.SigTypeEdDSASha512Ed25519, date,
//	)
//	if !VerifyBlindedSignature(blindedDest, originalDest, alpha) {
//	    return errors.New("blinded destination verification failed")
//	}
//
// Spec: https://geti2p.net/spec/encryptedleaseset §"Blinding Calculations"
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

// extractEd25519SigningKey validates that the destination uses a blinding-capable
// signature type and returns its 32-byte signing public key.
//
// Ed25519 (7) and RedDSA (11) both use 32-byte keys on the same curve and are the
// only types the spec permits for blinding ("Signing public key in unblinded
// destination must be Ed25519 (sig type 7) or Red25519 (sig type 11)"). Accepting
// only type 7 here would make VerifyBlindedSignature reject a blinded destination
// assembled from a RedDSA original, because the blinded key certificate declares
// type 11 as the spec requires.
func extractEd25519SigningKey(dest destination.Destination) ([32]byte, error) {
	var result [32]byte
	sigType := dest.KeyCertificate.SigningPublicKeyType()
	if sigType != key_certificate.KEYCERT_SIGN_ED25519 &&
		sigType != key_certificate.KEYCERT_SIGN_REDDSA_ED25519 {
		return result, oops.Errorf("destination does not use Ed25519 or RedDSA (sig type %d)", sigType)
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
func compareBlindedKeys(origPubKey, blindedPubKey, alpha [32]byte) bool {
	expectedBlindedKey, err := ed25519.BlindPublicKey(origPubKey, alpha)
	if err != nil {
		return false
	}
	return expectedBlindedKey == blindedPubKey
}
