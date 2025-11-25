// Package destination implements the I2P Destination common data structure
package destination

import (
	"strings"

	"github.com/go-i2p/logger"

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
func ReadDestination(data []byte) (destination Destination, remainder []byte, err error) {
	log.WithFields(logger.Fields{
		"input_length": len(data),
	}).Debug("Reading Destination from bytes")

	keys_and_cert_obj, remainder, err := keys_and_cert.ReadKeysAndCert(data)
	destination = Destination{
		keys_and_cert_obj,
	}

	log.WithFields(logger.Fields{
		"remainder_length": len(remainder),
	}).Debug("Successfully read Destination from bytes")

	return
}

// Bytes returns the binary representation of the Destination.
// This serializes the destination back to []byte format for storage or transmission.
// Returns an error if the destination is not properly initialized.
func (destination Destination) Bytes() ([]byte, error) {
	log.Debug("Serializing Destination to bytes")

	bytes, err := destination.KeysAndCert.Bytes()
	if err != nil {
		return nil, err
	}

	log.WithFields(logger.Fields{
		"bytes_length": len(bytes),
	}).Debug("Successfully serialized Destination to bytes")

	return bytes, nil
}

// Base32Address returns the I2P base32 address for this Destination.
// Returns an error if the destination is not properly initialized.
func (destination Destination) Base32Address() (string, error) {
	log.Debug("Generating Base32 address for Destination")

	dest, err := destination.KeysAndCert.Bytes()
	if err != nil {
		return "", err
	}
	hash := types.SHA256(dest)
	str := strings.Trim(base32.EncodeToString(hash[:]), "=")
	str = str + I2P_BASE32_SUFFIX

	log.WithFields(logger.Fields{
		"base32_address": str,
	}).Debug("Generated Base32 address for Destination")

	return str, nil
}

// Base64 returns the I2P base64 address for this Destination.
// Returns an error if the destination is not properly initialized.
func (destination Destination) Base64() (string, error) {
	log.Debug("Generating Base64 address for Destination")

	dest, err := destination.KeysAndCert.Bytes()
	if err != nil {
		return "", err
	}
	base64Address := base64.EncodeToString(dest)

	log.WithFields(logger.Fields{
		"base64_address_length": len(base64Address),
	}).Debug("Generated Base64 address for Destination")

	return base64Address, nil
}
