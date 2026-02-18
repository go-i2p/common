// Package router_info implements the I2P RouterInfo common data structure
package router_info

import (
	"crypto/ed25519"
	"crypto/sha512"

	"github.com/go-i2p/common/signature"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

var log = logger.GetGoI2PLogger()

// VerifySignature verifies the RouterInfo signature against the serialized data
// using the signing public key from the router identity.
// Currently supports Ed25519 (type 7) signature verification.
//
// Note: This implementation pre-hashes the data with SHA-512 before calling
// ed25519.Verify, consistent with the go-i2p/crypto Ed25519 signer convention.
// Standard I2P routers use pure Ed25519 (RFC 8032 PureEdDSA) where the Ed25519
// algorithm itself performs the double-SHA-512 internally. Signatures created
// by this library will verify correctly here, but signatures from standard I2P
// routers (Java I2P, i2pd) will NOT verify due to this non-standard pre-hash.
// This is a known limitation of the go-i2p/crypto library.
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
		// The go-i2p Ed25519 signer pre-hashes data with SHA-512 before signing,
		// matching the I2P EdDSA-SHA512-Ed25519 convention.
		h := sha512.Sum512(dataBytes)
		return ed25519.Verify(keyBytes, h[:], sigBytes), nil
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
