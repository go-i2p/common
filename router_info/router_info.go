// Package router_info implements the I2P RouterInfo common data structure
package router_info

import (
	"github.com/go-i2p/common/signature"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

var log = logger.GetGoI2PLogger()

// VerifySignature verifies the RouterInfo signature against the serialized data
// using the signing public key from the router identity.
// Supports all modern signature types (Ed25519, ECDSA P256/P384/P521, Ed25519ph,
// RedDSA) via the generic types.Verifier interface. Legacy types (DSA_SHA1, RSA)
// return explicit "legacy unsupported" errors.
//
// This implementation delegates to SigningPublicKey.NewVerifier().Verify(),
// which is consistent with the I2P specification's algorithm-agnostic design.
func (ri *RouterInfo) VerifySignature() (bool, error) {
	if err := validateSignaturePrerequisites(ri); err != nil {
		return false, err
	}

	dataBytes, err := ri.serializeWithoutSignature()
	if err != nil {
		return false, oops.Errorf("failed to serialize data for verification: %w", err)
	}

	return verifyRouterInfoSignature(ri, dataBytes)
}

// validateSignaturePrerequisites checks that all required components for signature
// verification are present and non-nil.
func validateSignaturePrerequisites(ri *RouterInfo) error {
	if ri == nil {
		return oops.Errorf("router info is nil")
	}
	if ri.router_identity == nil {
		return oops.Errorf("router identity is nil")
	}
	if ri.signature == nil {
		return oops.Errorf("signature is nil")
	}
	return nil
}

// verifyRouterInfoSignature performs the actual cryptographic signature verification
// using the SigningPublicKey interface. Supports all modern signature types
// (Ed25519, ECDSA P256/P384/P521, Ed25519ph, RedDSA) via the generic Verifier
// interface. Legacy types (DSA_SHA1, RSA) return explicit "legacy unsupported" errors.
func verifyRouterInfoSignature(ri *RouterInfo, dataBytes []byte) (bool, error) {
	sigBytes := ri.signature.Bytes()
	signingKey, err := ri.router_identity.SigningPublicKey()
	if err != nil {
		return false, oops.Errorf("failed to get signing public key: %w", err)
	}
	if signingKey == nil {
		return false, oops.Errorf("signing public key is nil")
	}

	sigType := ri.signature.Type()

	if err := checkLegacySignatureType(sigType); err != nil {
		return false, err
	}

	verifier, err := signingKey.NewVerifier()
	if err != nil {
		return false, oops.Errorf("failed to create verifier for signature type %d: %w", sigType, err)
	}

	err = verifier.Verify(dataBytes, sigBytes)
	if err != nil {
		log.WithFields(logger.Fields{
			"sig_type": sigType,
			"error":    err,
		}).Debug("Signature verification failed")
		return false, nil
	}
	return true, nil
}

// checkLegacySignatureType returns an error for legacy signature types that are
// intentionally unsupported (DSA_SHA1, RSA variants). These types are deprecated
// since I2P 0.9.58 (the Ed25519 mandate release). Returns nil for modern types.
func checkLegacySignatureType(sigType int) error {
	switch sigType {
	case signature.SIGNATURE_TYPE_DSA_SHA1:
		return oops.Errorf("legacy unsupported signature type: DSA_SHA1 (type %d) is deprecated since 0.9.58", sigType)
	case signature.SIGNATURE_TYPE_RSA_SHA256_2048,
		signature.SIGNATURE_TYPE_RSA_SHA384_3072,
		signature.SIGNATURE_TYPE_RSA_SHA512_4096:
		return oops.Errorf("legacy unsupported signature type: RSA (type %d) is deprecated since 0.9.58", sigType)
	default:
		return nil
	}
}

// Validate checks if the RouterInfo is properly initialized.
// Returns an error if the router info or its required components are invalid.
func (ri *RouterInfo) Validate() error {
	if ri == nil {
		return oops.Errorf("router info is nil")
	}
	if err := validateRouterIdentity(ri); err != nil {
		return err
	}
	if err := validateTimestampAndSize(ri); err != nil {
		return err
	}
	return validateAddressesAndOptions(ri)
}

// validateRouterIdentity validates the router identity is present and valid.
func validateRouterIdentity(ri *RouterInfo) error {
	if ri.router_identity == nil {
		return oops.Errorf("router identity is required")
	}
	if err := ri.router_identity.Validate(); err != nil {
		return oops.Errorf("invalid router identity: %w", err)
	}
	return nil
}

// validateTimestampAndSize validates the published date and size fields are present
// and have valid values.
func validateTimestampAndSize(ri *RouterInfo) error {
	if ri.published == nil {
		return oops.Errorf("published date is required")
	}
	if ri.published.IsZero() {
		return oops.Errorf("published date cannot be zero")
	}
	if ri.size == nil {
		return oops.Errorf("size field is required")
	}
	return nil
}

// validateAddressesAndOptions validates that the address count matches the size
// field and that options and signature are properly set.
// Note: The I2P spec allows 0 addresses (size is "0-255"), so we do not reject
// a RouterInfo with zero addresses at the structural validation level.
func validateAddressesAndOptions(ri *RouterInfo) error {
	sizeValue := ri.size.Int()
	if sizeValue != len(ri.addresses) {
		return oops.Errorf("size mismatch: size field is %d but have %d addresses", sizeValue, len(ri.addresses))
	}
	if ri.options == nil {
		return oops.Errorf("options mapping is required")
	}
	if err := ri.options.Validate(); err != nil {
		return oops.Errorf("invalid options mapping: %w", err)
	}
	if ri.signature == nil {
		return oops.Errorf("signature is required")
	}
	return nil
}

// IsValid returns true if the RouterInfo is properly initialized.
// This is a convenience method that returns false instead of an error.
func (ri *RouterInfo) IsValid() bool {
	return ri.Validate() == nil
}
