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
	if ri == nil {
		return false, oops.Errorf("router info is nil")
	}
	if ri.router_identity == nil {
		return false, oops.Errorf("router identity is nil")
	}
	if ri.signature == nil {
		return false, oops.Errorf("signature is nil")
	}

	dataBytes, err := ri.serializeWithoutSignature()
	if err != nil {
		return false, oops.Errorf("failed to serialize data for verification: %w", err)
	}

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
		// Standard Ed25519 (PureEdDSA per RFC 8032) — pass raw data directly
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
	if ri.router_identity == nil {
		return oops.Errorf("router identity is required")
	}
	if err := ri.router_identity.Validate(); err != nil {
		return oops.Errorf("invalid router identity: %w", err)
	}
	if ri.published == nil {
		return oops.Errorf("published date is required")
	}
	if ri.published.IsZero() {
		return oops.Errorf("published date cannot be zero")
	}
	if ri.size == nil {
		return oops.Errorf("size field is required")
	}
	if len(ri.addresses) == 0 {
		return oops.Errorf("router must have at least one address")
	}
	// Validate the size matches the actual number of addresses
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
