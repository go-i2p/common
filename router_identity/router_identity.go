// Package router_identity implements the I2P RouterIdentity common data structure
package router_identity

import (
	"github.com/go-i2p/common/key_certificate"
	"github.com/go-i2p/common/keys_and_cert"
	"github.com/samber/oops"
)

// NewRouterIdentityFromKeysAndCert creates a new RouterIdentity from KeysAndCert.
// This is a simpler alternative to NewRouterIdentity for cases where you already have a KeysAndCert.
// A defensive deep copy is made; the caller may freely mutate the original *KeysAndCert
// after this call without affecting the RouterIdentity.
//
// Deep copy semantics:
//   - KeyCertificate is cloned by re-parsing its bytes, giving it an independent
//     Certificate.payload backing array.
//   - Padding is cloned via make+copy.
//   - ReceivingPublic and SigningPublic are interface values; for production key types
//     backed by fixed-size Go arrays the struct copy creates independent values.
//     Slice-backed test implementations share the underlying array — see
//     TestNewRouterIdentityFromKeysAndCert_DefensiveCopy for documented behaviour.
//
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

	// Defensive deep copy: clone struct, then independently copy pointer/slice fields.
	kacCopy := *keysAndCert

	// Deep copy KeyCertificate by re-parsing its wire bytes, giving an independent
	// Certificate.payload backing array (fixes the shallow-copy aliasing risk).
	if keysAndCert.KeyCertificate != nil {
		certBytes := keysAndCert.KeyCertificate.Certificate.RawBytes()
		newKeyCert, _, err := key_certificate.NewKeyCertificate(certBytes)
		if err != nil {
			return nil, oops.Errorf("internal error: failed to deep-copy KeyCertificate: %w", err)
		}
		kacCopy.KeyCertificate = newKeyCert
	}

	// Deep copy Padding slice backing array.
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
