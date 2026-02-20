// Package router_identity implements the I2P RouterIdentity common data structure
package router_identity

import (
	"github.com/go-i2p/common/keys_and_cert"
	"github.com/samber/oops"
)

// NewRouterIdentityFromKeysAndCert creates a new RouterIdentity from KeysAndCert.
// This is a simpler alternative to NewRouterIdentity for cases where you already have a KeysAndCert.
// A defensive deep copy is made; the caller may freely mutate the original *KeysAndCert
// after this call without affecting the RouterIdentity.
// Returns an error if the provided KeysAndCert is invalid or uses prohibited key types.
func NewRouterIdentityFromKeysAndCert(keysAndCert *keys_and_cert.KeysAndCert) (*RouterIdentity, error) {
	if keysAndCert == nil {
		return nil, oops.Errorf("KeysAndCert cannot be nil")
	}
	if err := keysAndCert.Validate(); err != nil {
		return nil, oops.Errorf("invalid KeysAndCert: %w", err)
	}
	if err := validateRouterIdentityKeyTypes(keysAndCert); err != nil {
		return nil, err
	}
	logDeprecatedKeyTypes(keysAndCert.KeyCertificate)

	// Defensive deep copy: clone struct, KeyCertificate pointer, and Padding slice.
	kacCopy := *keysAndCert
	if keysAndCert.KeyCertificate != nil {
		keyCertCopy := *keysAndCert.KeyCertificate
		kacCopy.KeyCertificate = &keyCertCopy
	}
	if keysAndCert.Padding != nil {
		paddingCopy := make([]byte, len(keysAndCert.Padding))
		copy(paddingCopy, keysAndCert.Padding)
		kacCopy.Padding = paddingCopy
	}

	return &RouterIdentity{
		KeysAndCert: &kacCopy,
	}, nil
}

// NewRouterIdentityFromBytes creates a RouterIdentity by parsing bytes.
// This is an alias for ReadRouterIdentity with clearer naming.
// Returns the parsed RouterIdentity, remaining bytes, and any errors encountered.
func NewRouterIdentityFromBytes(data []byte) (*RouterIdentity, []byte, error) {
	ri, remainder, err := ReadRouterIdentity(data)
	if err != nil {
		return nil, remainder, err
	}
	return ri, remainder, nil
}

// Validate checks if the RouterIdentity is properly initialized and uses
// permitted key types per the I2P specification. Returns an error if the
// router identity or its components are invalid, or if prohibited key types
// (RedDSA, RSA, Ed25519ph signing; MLKEM crypto) are present.
func (ri *RouterIdentity) Validate() error {
	if ri == nil {
		return oops.Errorf("router identity is nil")
	}
	if ri.KeysAndCert == nil {
		return oops.Errorf("router identity KeysAndCert is nil")
	}
	if err := ri.KeysAndCert.Validate(); err != nil {
		return err
	}
	return validateRouterIdentityKeyTypes(ri.KeysAndCert)
}

// IsValid returns true if the RouterIdentity is properly initialized.
// This is a convenience method that returns false instead of an error.
func (ri *RouterIdentity) IsValid() bool {
	return ri.Validate() == nil
}
