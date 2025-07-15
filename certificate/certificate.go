// Package certificate implements the certificate common-structure of I2P.
package certificate

import (
	"encoding/binary"
	"fmt"

	"github.com/samber/oops"
	"github.com/sirupsen/logrus"

	"github.com/go-i2p/common/data"
)

// readCertificate creates a new Certificate from []byte
// Deprecated: Use ReadCertificate instead. This function will be removed in v2.0.
func readCertificate(data []byte) (certificate Certificate, err error) {
	log.WithFields(logrus.Fields{
		"at":     "readCertificate",
		"reason": "deprecated function called",
	}).Debug("readCertificate is deprecated, use ReadCertificate instead")

	certificate, _, err = ReadCertificate(data)
	return
}

// ReadCertificate creates a Certificate from []byte and returns any ExcessBytes at the end of the input.
// returns err if the certificate could not be read.
func ReadCertificate(data []byte) (certificate Certificate, remainder []byte, err error) {
	certificate, err = parseCertificateFromData(data)
	if err != nil {
		return
	}

	err = normalizeErrorConditions(err)
	remainder = calculateRemainder(data, certificate)

	logCertificateReadCompletion(certificate, data, remainder)
	return
}

// parseCertificateFromData constructs a Certificate based on the input data length and content.
func parseCertificateFromData(bytes []byte) (Certificate, error) {
	certificate := Certificate{}

	switch len(bytes) {
	case 0:
		return handleEmptyCertificateData(certificate)
	case 1, 2:
		return handleShortCertificateData(certificate, bytes)
	default:
		return handleValidCertificateData(certificate, bytes)
	}
}

// handleEmptyCertificateData processes the case where no data is provided.
func handleEmptyCertificateData(certificate Certificate) (Certificate, error) {
	certificate.kind = data.Integer([]byte{CERT_EMPTY_PAYLOAD_SIZE})
	certificate.len = data.Integer([]byte{CERT_EMPTY_PAYLOAD_SIZE})
	log.WithFields(logrus.Fields{
		"at":                       "(Certificate) ReadCertificate",
		"certificate_bytes_length": CERT_EMPTY_PAYLOAD_SIZE,
		"reason":                   "too short (len < CERT_MIN_SIZE)" + fmt.Sprintf("%d", certificate.kind.Int()),
	}).Error("invalid certificate, empty")
	return certificate, oops.Errorf("error parsing certificate: certificate is empty")
}

// handleShortCertificateData processes the case where insufficient data is provided.
func handleShortCertificateData(certificate Certificate, bytes []byte) (Certificate, error) {
	certificate.kind = data.Integer(bytes[CERT_EMPTY_PAYLOAD_SIZE : len(bytes)-CERT_DEFAULT_TYPE_SIZE])
	certificate.len = data.Integer([]byte{CERT_EMPTY_PAYLOAD_SIZE})
	log.WithFields(logrus.Fields{
		"at":                       "(Certificate) ReadCertificate",
		"certificate_bytes_length": len(bytes),
		"reason":                   "too short (len < CERT_MIN_SIZE)" + fmt.Sprintf("%d", certificate.kind.Int()),
	}).Error("invalid certificate, too short")
	return certificate, oops.Errorf("error parsing certificate: certificate is too short")
}

// handleValidCertificateData processes the case where sufficient data is available.
func handleValidCertificateData(certificate Certificate, bytes []byte) (Certificate, error) {
	certificate.kind = data.Integer(bytes[0:CERT_TYPE_FIELD_END])
	certificate.len = data.Integer(bytes[CERT_LENGTH_FIELD_START:CERT_LENGTH_FIELD_END])
	payloadLength := len(bytes) - CERT_MIN_SIZE
	certificate.payload = bytes[CERT_MIN_SIZE:]

	if err := validateCertificatePayloadLength(certificate, bytes, payloadLength); err != nil {
		return certificate, err
	}

	log.WithFields(logrus.Fields{
		"type":   certificate.kind.Int(),
		"length": certificate.len.Int(),
	}).Debug("Successfully created new certificate")

	return certificate, nil
}

// validateCertificatePayloadLength checks if the payload length matches the declared length.
func validateCertificatePayloadLength(certificate Certificate, bytes []byte, payloadLength int) error {
	if certificate.len.Int() > len(bytes)-CERT_MIN_SIZE {
		err := oops.Errorf("certificate parsing warning: certificate data is shorter than specified by length")
		log.WithFields(logrus.Fields{
			"at":                         "(Certificate) ReadCertificate",
			"certificate_bytes_length":   certificate.len.Int(),
			"certificate_payload_length": payloadLength,
			"data_bytes:":                string(bytes),
			"kind_bytes":                 bytes[0:CERT_TYPE_FIELD_END],
			"len_bytes":                  bytes[CERT_LENGTH_FIELD_START:CERT_LENGTH_FIELD_END],
			"reason":                     err.Error(),
		}).Error("invalid certificate, shorter than specified by length")
		return err
	}
	return nil
}

// normalizeErrorConditions handles specific error conditions that should not be treated as errors.
func normalizeErrorConditions(err error) error {
	if err != nil && err.Error() == "certificate parsing warning: certificate data is longer than specified by length" {
		log.Warn("Certificate data longer than specified length")
		return nil
	}
	return err
}

// calculateRemainder determines the remaining bytes after the complete certificate.
func calculateRemainder(data []byte, certificate Certificate) []byte {
	certLength := certificate.length()
	if len(data) > certLength {
		return data[certLength:]
	}
	return nil
}

// logCertificateReadCompletion logs detailed information about the completed certificate reading operation.
func logCertificateReadCompletion(certificate Certificate, data []byte, remainder []byte) {
	log.WithFields(logrus.Fields{
		"certificate_length": certificate.length(),
		"input_length":       len(data),
		"remainder_length":   len(remainder),
	}).Debug("Read certificate and calculated remainder")
}

// GetSignatureTypeFromCertificate extracts the signature type from a KEY certificate.
// Returns an error if the certificate is not a KEY type or if the payload is too short.
func GetSignatureTypeFromCertificate(cert Certificate) (int, error) {
	if cert.Type() != CERT_KEY {
		return CERT_EMPTY_PAYLOAD_SIZE, oops.Errorf("unexpected certificate type: %d", cert.Type())
	}
	if len(cert.payload) < CERT_MIN_KEY_PAYLOAD_SIZE {
		return CERT_EMPTY_PAYLOAD_SIZE, oops.Errorf("certificate payload too short to contain signature type")
	}
	sigType := int(binary.BigEndian.Uint16(cert.payload[CERT_KEY_SIG_TYPE_OFFSET:CERT_SIGNING_KEY_TYPE_SIZE])) // Read signing public key type from correct offset
	return sigType, nil
}
