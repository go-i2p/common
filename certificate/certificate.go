// Package certificate implements the certificate common-structure of I2P.
package certificate

import (
	"encoding/binary"
	"fmt"

	"github.com/go-i2p/logger"
	"github.com/samber/oops"

	"github.com/go-i2p/common/data"
)

// ReadCertificate creates a Certificate from []byte and returns any remaining bytes after the certificate.
// Returns nil certificate on error (not partial certificate).
// Per the I2P spec, type-specific payload length constraints are enforced as hard errors.
func ReadCertificate(data []byte) (certificate *Certificate, remainder []byte, err error) {
	cert, err := parseCertificateFromData(data)
	if err != nil {
		// Return nil certificate on error, not partial certificate
		return nil, data, err
	}

	// Validate type-specific payload constraints per spec — enforced as errors, not warnings.
	// Unknown certificate types (>CERT_KEY) are logged as warnings for forward compatibility.
	if err := validateTypeSpecificPayload(cert); err != nil {
		log.WithFields(logger.Fields{
			"at":     "ReadCertificate",
			"reason": err.Error(),
		}).Error("certificate type-specific validation failed")
		return nil, data, err
	}

	remainder = calculateRemainder(data, cert)

	logCertificateReadCompletion(cert, data, remainder)
	return &cert, remainder, nil
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
	log.WithFields(logger.Fields{
		"at":     "(Certificate) ReadCertificate",
		"reason": "too short (len < CERT_MIN_SIZE), empty input",
	}).Error("invalid certificate, empty")
	return certificate, oops.Errorf("error parsing certificate: certificate is empty")
}

// handleShortCertificateData processes the case where insufficient data is provided.
func handleShortCertificateData(certificate Certificate, bytes []byte) (Certificate, error) {
	log.WithFields(logger.Fields{
		"at":                       "(Certificate) ReadCertificate",
		"certificate_bytes_length": len(bytes),
		"reason":                   fmt.Sprintf("too short (len < CERT_MIN_SIZE), got %d bytes", len(bytes)),
	}).Error("invalid certificate, too short")
	return certificate, oops.Errorf("error parsing certificate: certificate is too short")
}

// handleValidCertificateData processes the case where sufficient data is available.
func handleValidCertificateData(certificate Certificate, bytes []byte) (Certificate, error) {
	// Defensive copy of all fields to prevent data aliasing.
	// Without copying, mutation of the source byte slice would silently
	// corrupt the certificate's kind, len, and payload fields.
	kindCopy := make([]byte, CERT_TYPE_FIELD_END)
	copy(kindCopy, bytes[0:CERT_TYPE_FIELD_END])
	certificate.kind = data.Integer(kindCopy)

	lenCopy := make([]byte, CERT_LENGTH_FIELD_END-CERT_LENGTH_FIELD_START)
	copy(lenCopy, bytes[CERT_LENGTH_FIELD_START:CERT_LENGTH_FIELD_END])
	certificate.len = data.Integer(lenCopy)

	availableLen := len(bytes) - CERT_MIN_SIZE
	if err := validateCertificatePayloadLength(certificate, bytes, availableLen); err != nil {
		return certificate, err
	}

	// Store only the declared-length bytes. Bytes beyond the declared boundary
	// belong to subsequent structures in the stream and must not be captured here.
	declaredLen := certificate.len.Int()
	payloadCopy := make([]byte, declaredLen)
	copy(payloadCopy, bytes[CERT_MIN_SIZE:CERT_MIN_SIZE+declaredLen])
	certificate.payload = payloadCopy

	log.WithFields(logger.Fields{
		"type":   certificate.kind.Int(),
		"length": certificate.len.Int(),
	}).Debug("Successfully created new certificate")

	return certificate, nil
}

// validateCertificatePayloadLength checks if the payload length matches the declared length.
func validateCertificatePayloadLength(certificate Certificate, bytes []byte, payloadLength int) error {
	if certificate.len.Int() > len(bytes)-CERT_MIN_SIZE {
		err := oops.Errorf("certificate parsing warning: certificate data is shorter than specified by length")
		log.WithFields(logger.Fields{
			"at":                         "(Certificate) ReadCertificate",
			"certificate_bytes_length":   certificate.len.Int(),
			"certificate_payload_length": payloadLength,
			"input_length":               len(bytes),
			"kind_bytes":                 bytes[0:CERT_TYPE_FIELD_END],
			"len_bytes":                  bytes[CERT_LENGTH_FIELD_START:CERT_LENGTH_FIELD_END],
			"reason":                     err.Error(),
		}).Error("invalid certificate, shorter than specified by length")
		return err
	}
	return nil
}

// validateTypeSpecificPayload enforces per the I2P spec that the payload length is
// correct for the certificate's declared type. Returns an error for known types with
// non-conforming payloads. Unknown types (>CERT_KEY) are only logged as warnings to
// preserve forward compatibility with future certificate types.
func validateTypeSpecificPayload(cert Certificate) error {
	certType := cert.kind.Int()
	payloadLen := cert.len.Int()

	switch certType {
	case CERT_NULL, CERT_HIDDEN:
		return validateEmptyTypePayload(certType, payloadLen)
	case CERT_HASHCASH:
		return validateHashcashTypePayload(cert, payloadLen)
	case CERT_SIGNED:
		return validateSignedTypePayload(payloadLen)
	case CERT_MULTIPLE:
		return validateMultipleTypePayload(payloadLen)
	case CERT_KEY:
		return validateKeyTypePayload(payloadLen)
	default:
		return handleUnknownCertType(certType)
	}
}

// validateEmptyTypePayload checks that NULL and HIDDEN certificates have zero-length payloads.
func validateEmptyTypePayload(certType, payloadLen int) error {
	if payloadLen != 0 {
		return oops.Errorf("certificate type %d should have empty payload, got %d bytes", certType, payloadLen)
	}
	return nil
}

// validateHashcashTypePayload checks that a HASHCASH certificate has a non-empty
// payload containing valid printable ASCII per the I2P spec.
func validateHashcashTypePayload(cert Certificate, payloadLen int) error {
	if payloadLen == 0 {
		return oops.Errorf("HASHCASH certificate payload must not be empty per spec")
	}
	return validateHashcashPayload(cert.payload[:payloadLen])
}

// validateSignedTypePayload checks that a SIGNED certificate payload has valid
// length (40 or 72 bytes) per the I2P spec.
func validateSignedTypePayload(payloadLen int) error {
	if payloadLen != CERT_SIGNED_PAYLOAD_SHORT && payloadLen != CERT_SIGNED_PAYLOAD_LONG {
		return oops.Errorf(
			"SIGNED certificate payload must be %d or %d bytes, got %d",
			CERT_SIGNED_PAYLOAD_SHORT, CERT_SIGNED_PAYLOAD_LONG, payloadLen,
		)
	}
	return nil
}

// validateMultipleTypePayload checks that a MULTIPLE certificate payload contains
// at least one complete sub-certificate (minimum 3 bytes).
func validateMultipleTypePayload(payloadLen int) error {
	if payloadLen < CERT_MIN_SIZE {
		return oops.Errorf("MULTIPLE certificate payload must contain at least one sub-certificate (%d bytes minimum), got %d",
			CERT_MIN_SIZE, payloadLen)
	}
	return nil
}

// validateKeyTypePayload checks that a KEY certificate payload meets the minimum
// size requirement.
func validateKeyTypePayload(payloadLen int) error {
	if payloadLen < CERT_MIN_KEY_PAYLOAD_SIZE {
		return oops.Errorf("KEY certificate payload too short: %d bytes (minimum %d)", payloadLen, CERT_MIN_KEY_PAYLOAD_SIZE)
	}
	return nil
}

// handleUnknownCertType logs a warning for unrecognized certificate types for
// forward compatibility with future certificate types.
func handleUnknownCertType(certType int) error {
	if certType > CERT_KEY {
		log.WithFields(logger.Fields{
			"cert_type": certType,
		}).Warn("unknown certificate type")
	}
	return nil
}

// validateHashcashPayload checks that a HASHCASH certificate payload contains valid
// ASCII characters per the I2P spec requirement of "an ASCII colon-separated hashcash string."
// The payload must be non-empty and contain only printable ASCII (0x20-0x7E).
func validateHashcashPayload(payload []byte) error {
	for i, b := range payload {
		if b < 0x20 || b > 0x7E {
			return oops.Errorf("HASHCASH certificate payload contains non-printable ASCII byte 0x%02x at offset %d", b, i)
		}
	}
	return nil
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
func logCertificateReadCompletion(certificate Certificate, data, remainder []byte) {
	log.WithFields(logger.Fields{
		"certificate_length": certificate.length(),
		"input_length":       len(data),
		"remainder_length":   len(remainder),
	}).Debug("Read certificate and calculated remainder")
}

// GetSignatureTypeFromCertificate extracts the signature type from a KEY certificate.
// Returns an error if the certificate is not a KEY type or if the payload is too short.
func GetSignatureTypeFromCertificate(cert Certificate) (int, error) {
	kind, err := cert.Type()
	if err != nil {
		log.WithFields(logger.Fields{"at": "GetSignatureTypeFromCertificate", "reason": "invalid certificate type"}).Error(err.Error())
		return -1, err
	}
	if kind != CERT_KEY {
		return -1, oops.Errorf("unexpected certificate type: %d", kind)
	}
	if len(cert.payload) < CERT_MIN_KEY_PAYLOAD_SIZE {
		return -1, oops.Errorf("certificate payload too short to contain signature type")
	}
	sigType := int(binary.BigEndian.Uint16(cert.payload[CERT_KEY_SIG_TYPE_OFFSET : CERT_KEY_SIG_TYPE_OFFSET+CERT_SIGNING_KEY_TYPE_SIZE])) // Read signing public key type from correct offset
	return sigType, nil
}

// GetCryptoTypeFromCertificate extracts the crypto public key type from a KEY certificate.
// Returns -1 (not 0) on every error path to avoid ambiguity with the valid ElGamal
// crypto type code 0. Callers must always check the returned error before using the int.
func GetCryptoTypeFromCertificate(cert Certificate) (int, error) {
	kind, err := cert.Type()
	if err != nil {
		log.WithFields(logger.Fields{"at": "GetCryptoTypeFromCertificate", "reason": "invalid certificate type"}).Error(err.Error())
		return -1, err
	}
	if kind != CERT_KEY {
		return -1, oops.Errorf("unexpected certificate type: %d", kind)
	}
	if len(cert.payload) < CERT_MIN_KEY_PAYLOAD_SIZE {
		return -1, oops.Errorf("certificate payload too short to contain crypto type")
	}
	cryptoType := int(binary.BigEndian.Uint16(cert.payload[CERT_KEY_CRYPTO_TYPE_OFFSET : CERT_KEY_CRYPTO_TYPE_OFFSET+CERT_CRYPTO_KEY_TYPE_SIZE]))
	return cryptoType, nil
}

// GetExcessSigningPublicKeyData extracts the excess signing public key bytes from a KEY
// certificate. For signing key types whose total length exceeds CERT_SPK_SLOT_SIZE (128)
// bytes, the overflow is stored starting at byte CERT_MIN_KEY_PAYLOAD_SIZE of the payload.
// Returns nil (no error) when signingKeySize <= CERT_SPK_SLOT_SIZE.
func GetExcessSigningPublicKeyData(cert Certificate, signingKeySize int) ([]byte, error) {
	kind, err := cert.Type()
	if err != nil {
		return nil, err
	}
	if kind != CERT_KEY {
		return nil, oops.Errorf("unexpected certificate type: %d", kind)
	}
	excessLen := signingKeySize - CERT_SPK_SLOT_SIZE
	if excessLen <= 0 {
		return nil, nil
	}
	if len(cert.payload) < CERT_MIN_KEY_PAYLOAD_SIZE+excessLen {
		return nil, oops.Errorf(
			"certificate payload too short for excess signing key data: need %d bytes, have %d",
			CERT_MIN_KEY_PAYLOAD_SIZE+excessLen, len(cert.payload),
		)
	}
	result := make([]byte, excessLen)
	copy(result, cert.payload[CERT_MIN_KEY_PAYLOAD_SIZE:CERT_MIN_KEY_PAYLOAD_SIZE+excessLen])
	return result, nil
}

// GetExcessCryptoPublicKeyData extracts the excess crypto public key bytes from a KEY
// certificate. For crypto key types whose total length exceeds CERT_CPK_SLOT_SIZE (256)
// bytes, the overflow is stored after any excess signing key data in the payload.
// The excessSigningLen parameter is the number of excess signing key bytes already
// stored before the crypto excess (= max(0, signingKeySize - CERT_SPK_SLOT_SIZE)).
// Returns nil (no error) when cryptoKeySize <= CERT_CPK_SLOT_SIZE.
func GetExcessCryptoPublicKeyData(cert Certificate, cryptoKeySize, excessSigningLen int) ([]byte, error) {
	kind, err := cert.Type()
	if err != nil {
		return nil, err
	}
	if kind != CERT_KEY {
		return nil, oops.Errorf("unexpected certificate type: %d", kind)
	}
	excessLen := cryptoKeySize - CERT_CPK_SLOT_SIZE
	if excessLen <= 0 {
		return nil, nil
	}
	offset := CERT_MIN_KEY_PAYLOAD_SIZE + excessSigningLen
	if len(cert.payload) < offset+excessLen {
		return nil, oops.Errorf(
			"certificate payload too short for excess crypto key data: need %d bytes, have %d",
			offset+excessLen, len(cert.payload),
		)
	}
	result := make([]byte, excessLen)
	copy(result, cert.payload[offset:offset+excessLen])
	return result, nil
}
