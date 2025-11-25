// Package destination implements the I2P Destination common data structure
package destination

import (
	"github.com/go-i2p/common/keys_and_cert"
	"github.com/samber/oops"
)

// NewDestination creates a new Destination from KeysAndCert.
// This is the primary constructor for creating destinations programmatically.
// Returns an error if the provided KeysAndCert is invalid.
func NewDestination(keysAndCert *keys_and_cert.KeysAndCert) (*Destination, error) {
	if keysAndCert == nil {
		return nil, oops.Errorf("KeysAndCert cannot be nil")
	}
	if err := keysAndCert.Validate(); err != nil {
		return nil, oops.Errorf("invalid KeysAndCert: %w", err)
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
