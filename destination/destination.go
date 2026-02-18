// Package destination implements the I2P Destination common data structure
package destination

import (
	"bytes"

	"github.com/go-i2p/common/key_certificate"
	"github.com/go-i2p/common/keys_and_cert"
	"github.com/go-i2p/crypto/types"
	"github.com/samber/oops"
)

// NewDestination creates a new Destination from KeysAndCert.
// This is the primary constructor for creating destinations programmatically.
// Returns an error if the provided KeysAndCert is invalid or uses prohibited key types.
func NewDestination(keysAndCert *keys_and_cert.KeysAndCert) (*Destination, error) {
	if keysAndCert == nil {
		return nil, oops.Errorf("KeysAndCert cannot be nil")
	}
	if err := keysAndCert.Validate(); err != nil {
		return nil, oops.Errorf("invalid KeysAndCert: %w", err)
	}
	if err := validateDestinationKeyTypes(keysAndCert); err != nil {
		return nil, err
	}

	return &Destination{
		KeysAndCert: keysAndCert,
	}, nil
}

// NewDestinationFromBytes creates a Destination by parsing bytes.
// NewDestinationFromBytes creates a Destination by parsing bytes.
// Returns a pointer for consistency with NewDestination.
// Returns the parsed Destination, remaining bytes, and any errors encountered.
func NewDestinationFromBytes(data []byte) (*Destination, []byte, error) {
	dest, remainder, err := ReadDestination(data)
	if err != nil {
		return nil, remainder, err
	}
	return &dest, remainder, nil
}

// Validate checks if the Destination is properly initialized.
// Returns an error if the destination or its components are invalid.
func (d *Destination) Validate() error {
	if d == nil {
		return oops.Errorf("destination is nil")
	}
	if d.KeysAndCert == nil {
		return oops.Errorf("destination KeysAndCert is nil")
	}
	return d.KeysAndCert.Validate()
}

// IsValid returns true if the Destination is properly initialized.
// This is a convenience method that returns false instead of an error.
func (d *Destination) IsValid() bool {
	return d.Validate() == nil
}

// Hash returns the SHA-256 hash of the Destination's binary representation.
// The I2P network database is keyed by SHA256(Destination).
// Returns an error if the destination is not properly initialized.
func (d *Destination) Hash() ([32]byte, error) {
	if d == nil || d.KeysAndCert == nil {
		return [32]byte{}, oops.Errorf("destination is not initialized")
	}
	b, err := d.KeysAndCert.Bytes()
	if err != nil {
		return [32]byte{}, err
	}
	return types.SHA256(b), nil
}

// Equals returns true if two Destinations are byte-for-byte identical.
// Returns false if either destination is nil or not properly initialized.
func (d *Destination) Equals(other *Destination) bool {
	if d == nil || other == nil {
		return false
	}
	if d.KeysAndCert == nil || other.KeysAndCert == nil {
		return false
	}
	dBytes, err := d.KeysAndCert.Bytes()
	if err != nil {
		return false
	}
	otherBytes, err := other.KeysAndCert.Bytes()
	if err != nil {
		return false
	}
	return bytes.Equal(dBytes, otherBytes)
}

// validateDestinationKeyTypes checks that the KeysAndCert does not use
// key types prohibited for Destinations. Per the I2P spec (0.9.67):
//   - Crypto: MLKEM512_X25519 (5), MLKEM768_X25519 (6), MLKEM1024_X25519 (7)
//     are "for Leasesets only, not for RIs or Destinations."
//   - Signing: RSA_SHA256_2048 (4), RSA_SHA384_3072 (5), RSA_SHA512_4096 (6)
//     are "Offline only; never used in Key Certificates for Destinations."
//   - Signing: EdDSA_SHA512_Ed25519ph (8) is "Offline only; never used in
//     Key Certificates for Destinations."
func validateDestinationKeyTypes(kac *keys_and_cert.KeysAndCert) error {
	if kac == nil || kac.KeyCertificate == nil {
		return nil
	}
	if err := validateDestinationCryptoType(kac); err != nil {
		return err
	}
	return validateDestinationSigningType(kac)
}

// validateDestinationCryptoType rejects crypto types prohibited for Destinations.
func validateDestinationCryptoType(kac *keys_and_cert.KeysAndCert) error {
	cryptoType := kac.KeyCertificate.PublicKeyType()
	switch cryptoType {
	case key_certificate.KEYCERT_CRYPTO_MLKEM512_X25519,
		key_certificate.KEYCERT_CRYPTO_MLKEM768_X25519,
		key_certificate.KEYCERT_CRYPTO_MLKEM1024_X25519:
		return oops.Errorf(
			"crypto type %d is not permitted for Destinations (LeaseSet only)",
			cryptoType,
		)
	}
	return nil
}

// validateDestinationSigningType rejects signing types prohibited for Destinations.
// RSA types (4-6) and Ed25519ph (8) are offline-only and never used in
// Key Certificates for Destinations per the I2P spec.
func validateDestinationSigningType(kac *keys_and_cert.KeysAndCert) error {
	signingType := kac.KeyCertificate.SigningPublicKeyType()
	switch signingType {
	case key_certificate.KEYCERT_SIGN_RSA2048,
		key_certificate.KEYCERT_SIGN_RSA3072,
		key_certificate.KEYCERT_SIGN_RSA4096:
		return oops.Errorf(
			"signing type %d (RSA) is not permitted for Destinations (offline only)",
			signingType,
		)
	case key_certificate.KEYCERT_SIGN_ED25519PH:
		return oops.Errorf(
			"signing type %d (Ed25519ph) is not permitted for Destinations (offline only)",
			signingType,
		)
	}
	return nil
}
