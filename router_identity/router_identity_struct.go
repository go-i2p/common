// Package router_identity implements the I2P RouterIdentity common data structure
package router_identity

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"

	"github.com/go-i2p/common/certificate"
	"github.com/go-i2p/common/destination"
	"github.com/go-i2p/common/key_certificate"
	"github.com/go-i2p/common/keys_and_cert"
	"github.com/go-i2p/crypto/types"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

var log = logger.GetGoI2PLogger()

/*
[RouterIdentity]
Accurate for version 0.9.67

Description
Defines the way to uniquely identify a particular router

Contents
Identical to KeysAndCert.
*/

// RouterIdentity is the represenation of an I2P RouterIdentity.
// Moved from: router_identity.go
//
// https://geti2p.net/spec/common-structures#routeridentity
type RouterIdentity struct {
	*keys_and_cert.KeysAndCert
}

// NewRouterIdentity creates a new RouterIdentity with the specified parameters.
// The caller is responsible for providing padding; for Proposal 161-compliant
// compressible padding, use NewRouterIdentityWithCompressiblePadding instead.
// Moved from: router_identity.go
func NewRouterIdentity(publicKey types.ReceivingPublicKey, signingPublicKey types.SigningPublicKey, cert *certificate.Certificate, padding []byte) (*RouterIdentity, error) {
	log.Debug("Creating new RouterIdentity")

	// Step 1: Create keyCertificate from the provided certificate.
	// Assuming NewKeyCertificate is a constructor that takes a Certificate and returns a keyCertificate.
	keyCert, err := key_certificate.KeyCertificateFromCertificate(cert)
	if err != nil {
		log.WithError(err).Error("KeyCertificateFromCertificate failed.")
		return nil, err
	}

	// Step 2: Create KeysAndCert instance.
	keysAndCert, err := keys_and_cert.NewKeysAndCert(keyCert, publicKey, padding, signingPublicKey)
	if err != nil {
		log.WithError(err).Error("NewKeysAndCert failed.")
		return nil, err
	}

	// Step 3: Validate key types are permitted for RouterIdentity.
	if err := validateRouterIdentityKeyTypes(keysAndCert); err != nil {
		return nil, err
	}

	// Step 4: Warn about deprecated key types.
	logDeprecatedKeyTypes(keyCert)

	// Step 5: Initialize RouterIdentity with KeysAndCert.
	routerIdentity := RouterIdentity{
		KeysAndCert: keysAndCert,
	}

	log.WithFields(logger.Fields{
		"public_key_type":         keyCert.PublicKeyType(),
		"signing_public_key_type": keyCert.SigningPublicKeyType(),
		"padding_length":          len(padding),
	}).Debug("Successfully created RouterIdentity")

	return &routerIdentity, nil
}

// NewRouterIdentityWithCompressiblePadding creates a new RouterIdentity and
// auto-generates Proposal 161-compliant compressible padding from the key
// certificate and key sizes. This is the recommended constructor for new
// Router Identities.
func NewRouterIdentityWithCompressiblePadding(
	publicKey types.ReceivingPublicKey,
	signingPublicKey types.SigningPublicKey,
	cert *certificate.Certificate,
) (*RouterIdentity, error) {
	keyCert, err := key_certificate.KeyCertificateFromCertificate(cert)
	if err != nil {
		return nil, err
	}
	paddingSize := keys_and_cert.KEYS_AND_CERT_DATA_SIZE -
		keyCert.CryptoSize() - keyCert.SigningPublicKeySize()
	if paddingSize < 0 {
		paddingSize = 0
	}
	padding, err := keys_and_cert.GenerateCompressiblePadding(paddingSize)
	if err != nil {
		return nil, oops.Errorf("failed to generate compressible padding: %w", err)
	}
	return NewRouterIdentity(publicKey, signingPublicKey, cert, padding)
}

// ReadRouterIdentity returns RouterIdentity from a []byte.
// The remaining bytes after the specified length are also returned.
// Returns a list of errors that occurred during parsing.
// Moved from: router_identity.go
func ReadRouterIdentity(data []byte) (ri *RouterIdentity, remainder []byte, err error) {
	log.WithFields(logger.Fields{
		"input_length": len(data),
	}).Debug("Reading RouterIdentity from data")
	kac, remainder, err := keys_and_cert.ReadKeysAndCert(data)
	if err != nil {
		log.WithError(err).Error("Failed to read KeysAndCert for RouterIdentity")
		return
	}
	if err = validateRouterIdentityKeyTypes(kac); err != nil {
		return nil, remainder, err
	}
	logDeprecatedKeyTypes(kac.KeyCertificate)
	ri = &RouterIdentity{
		kac,
	}
	log.WithFields(logger.Fields{
		"remainder_length": len(remainder),
	}).Debug("Successfully read RouterIdentity")
	return
}

// AsDestination converts the RouterIdentity to a Destination.
// Returns a deep copy; mutating the returned Destination does not affect
// the original RouterIdentity.
// Returns a zero-value Destination if the receiver or its KeysAndCert is nil.
func (ri *RouterIdentity) AsDestination() destination.Destination {
	if ri == nil || ri.KeysAndCert == nil {
		return destination.Destination{}
	}
	copy := *ri.KeysAndCert
	return destination.Destination{
		KeysAndCert: &copy,
	}
}

// Equal returns true if two RouterIdentities are byte-for-byte identical.
// Uses constant-time comparison to prevent timing side-channels.
// Returns false if either identity is nil or not properly initialized.
func (ri *RouterIdentity) Equal(other *RouterIdentity) bool {
	if ri == nil || other == nil {
		return false
	}
	if ri.KeysAndCert == nil || other.KeysAndCert == nil {
		return false
	}
	riBytes, err := ri.KeysAndCert.Bytes()
	if err != nil {
		return false
	}
	otherBytes, err := other.KeysAndCert.Bytes()
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(riBytes, otherBytes) == 1
}

// String returns a human-readable representation of the RouterIdentity,
// showing a truncated SHA-256 hash (16 bytes / 128 bits) of the serialized identity.
// Implements fmt.Stringer.
func (ri *RouterIdentity) String() string {
	if ri == nil || ri.KeysAndCert == nil {
		return "<nil RouterIdentity>"
	}
	b, err := ri.KeysAndCert.Bytes()
	if err != nil {
		return "<invalid RouterIdentity>"
	}
	hash := sha256.Sum256(b)
	return fmt.Sprintf("RouterIdentity{%s}", hex.EncodeToString(hash[:16]))
}

// validateRouterIdentityKeyTypes checks that the KeysAndCert does not use
// key types prohibited for Router Identities per the I2P specification.
// Returns an error if the KeyCertificate is nil (key types cannot be validated).
func validateRouterIdentityKeyTypes(kac *keys_and_cert.KeysAndCert) error {
	if kac == nil {
		return oops.Errorf("KeysAndCert cannot be nil for key type validation")
	}
	if kac.KeyCertificate == nil {
		return oops.Errorf("KeyCertificate is nil; cannot validate key types for Router Identity")
	}
	sigType := kac.KeyCertificate.SigningPublicKeyType()
	if desc, ok := disallowedSigningKeyTypes[sigType]; ok {
		return oops.Errorf(
			"signing key type %d (%s) is not permitted for Router Identities",
			sigType, desc,
		)
	}
	cryptoType := kac.KeyCertificate.PublicKeyType()
	if desc, ok := disallowedCryptoKeyTypes[cryptoType]; ok {
		return oops.Errorf(
			"crypto key type %d (%s) is not permitted for Router Identities",
			cryptoType, desc,
		)
	}
	return nil
}

// logDeprecatedKeyTypes emits warnings for deprecated key types
// used in Router Identities (ElGamal and DSA-SHA1).
func logDeprecatedKeyTypes(keyCert *key_certificate.KeyCertificate) {
	if keyCert == nil {
		return
	}
	if keyCert.PublicKeyType() == DEPRECATED_CRYPTO_ELGAMAL {
		log.Warn("RouterIdentity uses deprecated ElGamal crypto key type (0); use X25519 (4) for new identities")
	}
	if keyCert.SigningPublicKeyType() == DEPRECATED_SIGNING_DSA_SHA1 {
		log.Warn("RouterIdentity uses deprecated DSA-SHA1 signing key type (0); use Ed25519 (7) for new identities")
	}
}
