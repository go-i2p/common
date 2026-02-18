// Package router_info implements the I2P RouterInfo common data structure
package router_info

import (
	"crypto/ed25519"

	"github.com/go-i2p/common/signature"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

var log = logger.GetGoI2PLogger()

// VerifySignature verifies the RouterInfo signature against the serialized data
// using the signing public key from the router identity.
// Currently supports Ed25519 (type 7) signature verification.
//
// This implementation uses standard Ed25519 verification (RFC 8032 PureEdDSA),
// passing data directly to ed25519.Verify which performs its own internal
// SHA-512 hashing. This is consistent with Java I2P and i2pd.
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
// based on the signature type. Currently supports Ed25519 (type 7).
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
	switch sigType {
	case signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519:
		keyBytes := signingKey.Bytes()
		if len(keyBytes) != ed25519.PublicKeySize {
			return false, oops.Errorf("invalid Ed25519 public key size: %d", len(keyBytes))
		}
		return ed25519.Verify(keyBytes, dataBytes, sigBytes), nil
	default:
		return false, oops.Errorf("unsupported signature type for verification: %d", sigType)
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

// validateAddressesAndOptions validates that addresses are present, their count
// matches the size field, and that options and signature are properly set.
func validateAddressesAndOptions(ri *RouterInfo) error {
	if len(ri.addresses) == 0 {
		return oops.Errorf("router must have at least one address")
	}
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
