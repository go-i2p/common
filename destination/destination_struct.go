// Package destination implements the I2P Destination common data structure
package destination

import (
	"strings"

	"github.com/go-i2p/logger"
	"github.com/samber/oops"

	"github.com/go-i2p/common/keys_and_cert"
	"github.com/go-i2p/crypto/types"

	"github.com/go-i2p/common/base32"
	"github.com/go-i2p/common/base64"
)

/*
[Destination]
Accurate for version 0.9.67

Description
A Destination defines a particular endpoint to which messages can be directed for secure delivery.

Contents
Identical to KeysAndCert.
*/

// Destination is the representation of an I2P Destination.
//
// https://geti2p.net/spec/common-structures#destination
type Destination struct {
	*keys_and_cert.KeysAndCert
}

// ReadDestination returns Destination from a []byte.
// The remaining bytes after the specified length are also returned.
// Returns a list of errors that occurred during parsing.
func ReadDestination(data []byte) (Destination, []byte, error) {
	log.WithFields(logger.Fields{
		"input_length": len(data),
	}).Debug("Reading Destination from bytes")

	keysAndCertObj, remainder, err := keys_and_cert.ReadKeysAndCert(data)
	if err != nil {
		return Destination{}, remainder, err
	}

	d := Destination{keysAndCertObj}

	if err := validateDestinationKeyTypes(d.KeysAndCert); err != nil {
		return Destination{}, remainder, err
	}

	log.WithFields(logger.Fields{
		"remainder_length": len(remainder),
	}).Debug("Successfully read Destination from bytes")

	return d, remainder, nil
}

// Bytes returns the binary representation of the Destination.
// This serializes the destination back to []byte format for storage or transmission.
// Returns an error if the destination is not properly initialized.
// Uses a value receiver because the Destination struct contains only a pointer
// field, making copies cheap, and this preserves API compatibility.
func (d Destination) Bytes() ([]byte, error) {
	if d.KeysAndCert == nil {
		return nil, oops.Errorf("destination is not initialized: nil KeysAndCert")
	}
	log.Debug("Serializing Destination to bytes")

	b, err := d.KeysAndCert.Bytes()
	if err != nil {
		return nil, err
	}

	log.WithFields(logger.Fields{
		"bytes_length": len(b),
	}).Debug("Successfully serialized Destination to bytes")

	return b, nil
}

// Base32Address returns the I2P base32 address for this Destination.
// Returns an error if the destination is not properly initialized.
// Uses a value receiver for API compatibility with callers that receive
// Destination by value (e.g., from LeaseSet2.Destination()).
func (d Destination) Base32Address() (string, error) {
	if d.KeysAndCert == nil {
		return "", oops.Errorf("destination is not initialized: nil KeysAndCert")
	}
	log.Debug("Generating Base32 address for Destination")

	dest, err := d.KeysAndCert.Bytes()
	if err != nil {
		return "", err
	}
	hash := types.SHA256(dest)
	str := strings.TrimRight(base32.EncodeToString(hash[:]), "=")
	str = str + I2PBase32Suffix

	log.Debug("Generated Base32 address for Destination")

	return str, nil
}

// Base64 returns the I2P base64 address for this Destination.
// Returns an error if the destination is not properly initialized.
// Uses a value receiver for API compatibility with callers that receive
// Destination by value.
func (d Destination) Base64() (string, error) {
	if d.KeysAndCert == nil {
		return "", oops.Errorf("destination is not initialized: nil KeysAndCert")
	}
	log.Debug("Generating Base64 address for Destination")

	dest, err := d.KeysAndCert.Bytes()
	if err != nil {
		return "", err
	}
	base64Address := base64.EncodeToString(dest)

	log.Debug("Generated Base64 address for Destination")

	return base64Address, nil
}
