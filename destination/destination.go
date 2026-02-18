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
// This is an alias for ReadDestination with clearer naming.
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
// crypto types prohibited for Destinations. Per the I2P spec (0.9.67),
// MLKEM512_X25519 (5), MLKEM768_X25519 (6), and MLKEM1024_X25519 (7)
// are "for Leasesets only, not for RIs or Destinations."
func validateDestinationKeyTypes(kac *keys_and_cert.KeysAndCert) error {
	if kac == nil || kac.KeyCertificate == nil {
		return nil
	}
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
