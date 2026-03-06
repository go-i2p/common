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
	if err := validateKeysAndCertInput(keysAndCert); err != nil {
		return nil, err
	}

	kacCopy, err := deepCopyKeysAndCert(keysAndCert)
	if err != nil {
		return nil, err
	}

	logDeprecatedKeyTypes(kacCopy.KeyCertificate)

	return &RouterIdentity{
		KeysAndCert: kacCopy,
	}, nil
}

// validateKeysAndCertInput checks that the KeysAndCert is non-nil, valid, and
// uses permitted key types for a RouterIdentity.
func validateKeysAndCertInput(keysAndCert *keys_and_cert.KeysAndCert) error {
	if keysAndCert == nil {
		return oops.Errorf("KeysAndCert cannot be nil")
	}
	if err := keysAndCert.Validate(); err != nil {
		return oops.Errorf("invalid KeysAndCert: %w", err)
	}
	return validateRouterIdentityKeyTypes(keysAndCert)
}

// deepCopyKeysAndCert creates an independent deep copy of a KeysAndCert,
// cloning the KeyCertificate and Padding to avoid data aliasing.
func deepCopyKeysAndCert(keysAndCert *keys_and_cert.KeysAndCert) (*keys_and_cert.KeysAndCert, error) {
	kacCopy := *keysAndCert

	if keysAndCert.KeyCertificate != nil {
		certBytes := keysAndCert.KeyCertificate.Certificate.RawBytes()
		newKeyCert, _, err := key_certificate.NewKeyCertificate(certBytes)
		if err != nil {
			return nil, oops.Errorf("internal error: failed to deep-copy KeyCertificate: %w", err)
		}
		kacCopy.KeyCertificate = newKeyCert
	}

	if keysAndCert.Padding != nil {
		paddingCopy := make([]byte, len(keysAndCert.Padding))
		copy(paddingCopy, keysAndCert.Padding)
		kacCopy.Padding = paddingCopy
	}

	return &kacCopy, nil
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
