// Package destination implements the I2P Destination common data structure
package destination

import (
	"fmt"

	"github.com/go-i2p/logger"
	"github.com/samber/oops"

	"github.com/go-i2p/common/keys_and_cert"
	"github.com/go-i2p/crypto/types"

	"github.com/go-i2p/common/base32"
	"github.com/go-i2p/common/base64"
)

// Destination is the representation of an I2P Destination.
// Spec: https://geti2p.net/spec/common-structures#destination
type Destination struct {
	*keys_and_cert.KeysAndCert
}

// readDestinationRaw performs the core parse without canonicalization.
// Used internally by ReadDestination and CanonicalizeDestination to
// avoid infinite recursion.
func readDestinationRaw(data []byte) (Destination, []byte, error) {
	keysAndCertObj, remainder, err := keys_and_cert.ReadKeysAndCert(data)
	if err != nil {
		return Destination{}, remainder, err
	}

	d := Destination{keysAndCertObj}

	if err := validateDestinationKeyTypes(d.KeysAndCert); err != nil {
		return Destination{}, nil, err
	}

	return d, remainder, nil
}

// ReadDestination returns Destination from a []byte.
// The remaining bytes after the specified length are also returned.
// Returns a list of errors that occurred during parsing.
//
// For ElGamal+DSA-SHA1 destinations encoded with a KEY(0,0) certificate,
// the destination is automatically canonicalized to the NULL certificate
// form per the I2P specification. This ensures consistent SHA-256 hashing
// regardless of the wire encoding used by the sender.
func ReadDestination(data []byte) (Destination, []byte, error) {
	log.WithFields(logger.Fields{
		"pkg": "destination", "func": "ReadDestination",
		"input_length": len(data),
	}).Debug("Reading Destination from bytes")

	d, remainder, err := readDestinationRaw(data)
	if err != nil {
		return d, remainder, err
	}

	// Auto-canonicalize ElGamal+DSA-SHA1 destinations so that Hash() and
	// Equals() always produce consistent results regardless of whether the
	// sender used a NULL cert or KEY(0,0) cert encoding.
	canonical, canonErr := CanonicalizeDestination(&d)
	if canonErr == nil && canonical != nil {
		d = *canonical
	}

	log.WithFields(logger.Fields{
		"pkg": "destination", "func": "ReadDestination",
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
	log.WithFields(logger.Fields{"pkg": "destination", "func": "Destination.Bytes"}).Debug("Serializing Destination to bytes")

	b, err := d.KeysAndCert.Bytes()
	if err != nil {
		return nil, err
	}

	log.WithFields(logger.Fields{
		"pkg": "destination", "func": "Destination.Bytes",
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
	log.WithFields(logger.Fields{"pkg": "destination", "func": "Destination.Base32Address"}).Debug("Generating Base32 address for Destination")

	dest, err := d.KeysAndCert.Bytes()
	if err != nil {
		return "", err
	}
	hash := types.SHA256(dest)
	str := base32.EncodeToStringNoPadding(hash[:])
	str = str + I2PBase32Suffix

	log.WithFields(logger.Fields{"pkg": "destination", "func": "Destination.Base32Address"}).Debug("Generated Base32 address for Destination")

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
	log.WithFields(logger.Fields{"pkg": "destination", "func": "Destination.Base64"}).Debug("Generating Base64 address for Destination")

	dest, err := d.KeysAndCert.Bytes()
	if err != nil {
		return "", err
	}
	base64Address := base64.EncodeToString(dest)

	log.WithFields(logger.Fields{"pkg": "destination", "func": "Destination.Base64"}).Debug("Generated Base64 address for Destination")

	return base64Address, nil
}

// String returns the I2P base32 address as the default string representation.
// Implements the fmt.Stringer interface for convenient logging and debugging.
// Returns "<nil Destination>" if the destination is not properly initialized,
// or "<invalid Destination>" if address generation fails.
func (d Destination) String() string {
	if d.KeysAndCert == nil {
		return "<nil Destination>"
	}
	addr, err := d.Base32Address()
	if err != nil {
		return fmt.Sprintf("<invalid Destination: %s>", err.Error())
	}
	return addr
}
