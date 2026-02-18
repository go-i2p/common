// Package certificate implements the certificate common-structure of I2P.
package certificate

import (
	"github.com/go-i2p/logger"
	"github.com/samber/oops"

	"github.com/go-i2p/common/data"
)

var log = logger.GetGoI2PLogger()

/*
[I2P Certificate]
Accurate for version 0.9.67

Description
A certifificate is a container for various receipts of proof of works used throughout the I2P network.

Contents
1 byte Integer specifying certificate type, followed by a 2 byte Integer specifying the size of the certificate playload, then that many bytes.

+----+----+----+----+----+-//
|type| length  | payload
+----+----+----+----+----+-//

type :: Integer
		length -> 1 byte

		case 0 -> NULL
		case 1 -> HASHCASH
		case 2 -> HIDDEN
		case 3 -> SIGNED
		case 4 -> MULTIPLE
		case 5 -> KEY

length :: Integer
		  length -> 2 bytes

payload :: data
		   length -> $length bytes
*/

// Certificate is the representation of an I2P Certificate.
//
// https://geti2p.net/spec/common-structures#certificate
type Certificate struct {
	kind    data.Integer
	len     data.Integer
	payload []byte
}

// NewCertificate creates a new Certificate with default NULL type.
// The returned certificate serializes to exactly CERT_MIN_SIZE (3) bytes:
// 1 byte type (0x00 = NULL) + 2 byte length (0x0000) + 0 byte payload.
func NewCertificate() *Certificate {
	return &Certificate{
		kind:    data.Integer([]byte{CERT_NULL}),
		len:     data.Integer([]byte{0x00, 0x00}),
		payload: make([]byte, CERT_EMPTY_PAYLOAD_SIZE),
	}
}

// NewCertificateWithType creates a new Certificate with specified type and payload
func NewCertificateWithType(certType uint8, payload []byte) (*Certificate, error) {
	if err := validateCertType(certType); err != nil {
		return nil, err
	}

	if err := validateCertPayload(certType, payload); err != nil {
		return nil, err
	}

	return buildCertificate(certType, payload)
}

// validateCertType checks that the certificate type is a recognized value.
func validateCertType(certType uint8) error {
	switch certType {
	case CERT_NULL, CERT_HASHCASH, CERT_HIDDEN, CERT_SIGNED, CERT_MULTIPLE, CERT_KEY:
		return nil
	default:
		return oops.Errorf("invalid certificate type: %d", certType)
	}
}

// validateCertPayload checks that the payload satisfies the constraints for the
// given certificate type including maximum size and type-specific rules.
func validateCertPayload(certType uint8, payload []byte) error {
	if len(payload) > CERT_MAX_PAYLOAD_SIZE {
		return oops.Errorf("payload too long: %d bytes", len(payload))
	}
	if certType == CERT_NULL && len(payload) > CERT_EMPTY_PAYLOAD_SIZE {
		return oops.Errorf("NULL certificates must have empty payload")
	}
	if certType == CERT_HIDDEN && len(payload) > CERT_EMPTY_PAYLOAD_SIZE {
		return oops.Errorf("HIDDEN certificates must have empty payload per spec (total length 3)")
	}
	if certType == CERT_SIGNED && len(payload) != CERT_SIGNED_PAYLOAD_SHORT && len(payload) != CERT_SIGNED_PAYLOAD_LONG {
		return oops.Errorf("SIGNED certificates must have payload of %d or %d bytes, got %d",
			CERT_SIGNED_PAYLOAD_SHORT, CERT_SIGNED_PAYLOAD_LONG, len(payload))
	}
	return nil
}

// buildCertificate constructs a Certificate from a validated type and payload.
func buildCertificate(certType uint8, payload []byte) (*Certificate, error) {
	length, err := data.NewIntegerFromInt(len(payload), CERT_LENGTH_FIELD_SIZE)
	if err != nil {
		return nil, oops.Errorf("failed to create length integer: %w", err)
	}

	cert := &Certificate{
		kind:    data.Integer([]byte{certType}),
		len:     *length,
		payload: make([]byte, len(payload)),
	}

	if len(payload) > CERT_EMPTY_PAYLOAD_SIZE {
		copy(cert.payload, payload)
	}

	return cert, nil
}

// RawBytes returns the entire certificate in []byte form, includes excess payload data.
// Returns nil if the certificate is nil or not initialized.
func (c *Certificate) RawBytes() []byte {
	if !c.IsValid() {
		return nil
	}
	bytes := c.kind.Bytes()
	bytes = append(bytes, c.len.Bytes()...)
	bytes = append(bytes, c.payload...)
	log.WithFields(logger.Fields{
		"raw_bytes_length": len(bytes),
	}).Debug("Generated raw bytes for certificate")
	return bytes
}

// ExcessBytes returns the excess bytes in a certificate found after the specified payload length.
// Returns nil if the certificate is nil or not initialized.
func (c *Certificate) ExcessBytes() []byte {
	if !c.IsValid() {
		return nil
	}
	if len(c.payload) >= c.len.Int() {
		excess := c.payload[c.len.Int():]
		log.WithFields(logger.Fields{
			"excess_bytes_length": len(excess),
		}).Debug("Found excess bytes in certificate")
		return excess
	}
	log.Debug("No excess bytes found in certificate")
	return nil
}

// Bytes returns the entire certificate in []byte form, trims payload to specified length.
// Returns nil if the certificate is nil or not initialized.
func (c *Certificate) Bytes() []byte {
	if !c.IsValid() {
		return nil
	}
	bytes := c.kind.Bytes()
	bytes = append(bytes, c.len.Bytes()...)
	payload, err := c.Data()
	if err != nil {
		log.WithFields(logger.Fields{"at": "Certificate.Bytes", "reason": "invalid payload"}).Error(err.Error())
		// Return only type and length fields if payload is invalid
		return bytes
	}
	bytes = append(bytes, payload...)
	log.WithFields(logger.Fields{
		"bytes_length": len(bytes),
	}).Debug("Generated bytes for certificate")
	return bytes
}

// length returns the total certificate length in bytes.
// Returns 0 if the certificate is nil or not initialized.
// Optimized: uses direct arithmetic instead of allocating via Bytes().
func (c *Certificate) length() int {
	if !c.IsValid() {
		return 0
	}
	declaredLen := c.len.Int()
	actualPayloadLen := len(c.payload)
	payloadLen := declaredLen
	if actualPayloadLen < declaredLen {
		payloadLen = actualPayloadLen
	}
	return CERT_MIN_SIZE + payloadLen
}

// Type returns the certificate type as int, with validation and error context.
// The type is specified in the first byte of the Certificate.
func (c *Certificate) Type() (certType int, err error) {
	if !c.IsValid() {
		return 0, oops.Errorf("certificate is not initialized")
	}
	certType = c.kind.Int()
	if certType < CERT_NULL || certType > CERT_MAX_TYPE_VALUE {
		log.WithFields(logger.Fields{
			"at":        "Certificate.Type",
			"reason":    "invalid certificate type",
			"cert_type": certType,
		}).Error("Certificate type out of bounds")
		err = oops.Errorf("invalid certificate type: %d (must be 0-%d)", certType, CERT_MAX_TYPE_VALUE)
		return 0, err
	}
	log.WithFields(logger.Fields{
		"cert_type": certType,
	}).Debug("Retrieved certificate type")
	return certType, nil
}

// Length returns the payload length of a Certificate, with validation and error context.
func (c *Certificate) Length() (length int, err error) {
	if !c.IsValid() {
		return 0, oops.Errorf("certificate is not initialized")
	}
	length = c.len.Int()
	if length < CERT_EMPTY_PAYLOAD_SIZE || length > CERT_MAX_PAYLOAD_SIZE {
		log.WithFields(logger.Fields{
			"at":     "Certificate.Length",
			"reason": "invalid certificate length",
			"length": length,
		}).Error("Certificate length out of bounds")
		err = oops.Errorf("invalid certificate length: %d (must be 0-%d)", length, CERT_MAX_PAYLOAD_SIZE)
		return 0, err
	}
	log.WithFields(logger.Fields{
		"length": length,
	}).Debug("Retrieved certificate length")
	return length, nil
}

// Data returns the payload of a Certificate, trimmed to the declared length.
// Returns error if length is invalid.
func (c *Certificate) Data() (data []byte, err error) {
	length, lenErr := c.Length()
	if lenErr != nil {
		log.WithFields(logger.Fields{"at": "Certificate.Data", "reason": "invalid length"}).Error(lenErr.Error())
		return nil, lenErr
	}
	if length > len(c.payload) {
		data = c.payload
		log.Warn("Certificate payload shorter than specified length")
	} else {
		data = c.payload[0:length]
	}
	log.WithFields(logger.Fields{
		"data_length": len(data),
	}).Debug("Retrieved certificate data")
	return data, nil
}

// IsValid returns true if the certificate is fully initialized and valid.
// This method checks that all required fields (kind, len) are present and non-empty.
// Note: payload can be empty for NULL certificates.
func (c *Certificate) IsValid() bool {
	if c == nil {
		return false
	}
	if len(c.kind) == 0 {
		return false
	}
	if len(c.len) == 0 {
		return false
	}
	// payload can be empty for NULL certificates
	return true
}
