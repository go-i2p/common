// Package certificate implements the certificate common-structure of I2P.
package certificate

import (
	"encoding/binary"

	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// CertificateBuilder provides a fluent interface for building certificates.
// This pattern simplifies certificate construction, especially for complex cases
// with custom payloads or key types.
//
// Example usage:
//
//	cert, err := certificate.NewCertificateBuilder().
//	    WithKeyTypes(certificate.KEYCERT_SIGN_ED25519, certificate.KEYCERT_CRYPTO_X25519).
//	    Build()
type CertificateBuilder struct {
	certType    uint8
	payload     []byte
	signingType *int
	cryptoType  *int
	payloadSet  bool
}

// NewCertificateBuilder creates a new certificate builder with default NULL type.
func NewCertificateBuilder() *CertificateBuilder {
	return &CertificateBuilder{
		certType:   CERT_NULL,
		payload:    []byte{},
		payloadSet: false,
	}
}

// WithType sets the certificate type.
// Valid types are: CERT_NULL, CERT_HASHCASH, CERT_HIDDEN, CERT_SIGNED, CERT_MULTIPLE, CERT_KEY.
// Returns error if the certificate type is invalid.
//
// Example:
//
//	builder.WithType(certificate.CERT_KEY)
func (cb *CertificateBuilder) WithType(certType uint8) (*CertificateBuilder, error) {
	if !isValidCertType(certType) {
		return cb, oops.Errorf("invalid certificate type: %d", certType)
	}
	cb.certType = certType
	log.WithFields(logger.Fields{
		"cert_type": certType,
	}).Debug("Certificate builder: type set")
	return cb, nil
}

// WithKeyTypes sets signing and crypto key types (for CERT_KEY type).
// This is a convenience method that automatically:
//   - Sets the certificate type to CERT_KEY
//   - Builds the appropriate 4-byte payload
//
// Parameters:
//   - signingType: The signing key type (e.g., 7 for Ed25519)
//   - cryptoType: The crypto key type (e.g., 4 for X25519)
//
// Returns error if the key types are invalid (negative values).
//
// Example:
//
//	builder.WithKeyTypes(7, 4) // Ed25519 signing, X25519 crypto
func (cb *CertificateBuilder) WithKeyTypes(signingType, cryptoType int) (*CertificateBuilder, error) {
	if signingType < 0 {
		return cb, oops.Errorf("signing type cannot be negative: %d", signingType)
	}
	if cryptoType < 0 {
		return cb, oops.Errorf("crypto type cannot be negative: %d", cryptoType)
	}
	cb.certType = CERT_KEY
	cb.signingType = &signingType
	cb.cryptoType = &cryptoType
	cb.payloadSet = false // Key types will generate payload in Build()

	log.WithFields(logger.Fields{
		"signing_type": signingType,
		"crypto_type":  cryptoType,
	}).Debug("Certificate builder: key types set")

	return cb, nil
}

// WithPayload sets custom payload data.
// This overrides any payload that would be generated from key types.
//
// Example:
//
//	builder.WithType(certificate.CERT_SIGNED).WithPayload(signatureData)
func (cb *CertificateBuilder) WithPayload(payload []byte) *CertificateBuilder {
	cb.payload = make([]byte, len(payload))
	copy(cb.payload, payload)
	cb.payloadSet = true

	log.WithFields(logger.Fields{
		"payload_length": len(payload),
	}).Debug("Certificate builder: custom payload set")

	return cb
}

// Build creates the certificate with the configured options.
// Returns error if the configuration is invalid.
//
// Example:
//
//	cert, err := NewCertificateBuilder().
//	    WithKeyTypes(7, 4).
//	    Build()
func (cb *CertificateBuilder) Build() (*Certificate, error) {
	// Validate builder configuration
	if err := cb.Validate(); err != nil {
		return nil, oops.Errorf("invalid builder configuration: %w", err)
	}

	// Build payload if needed
	if err := cb.buildPayloadIfNeeded(); err != nil {
		return nil, err
	}

	// Create the certificate
	cert, err := NewCertificateWithType(cb.certType, cb.payload)
	if err != nil {
		return nil, oops.Errorf("failed to build certificate: %w", err)
	}

	log.WithFields(logger.Fields{
		"cert_type":      cb.certType,
		"payload_length": len(cb.payload),
	}).Debug("Certificate builder: successfully built certificate")

	return cert, nil
}

// Validate checks the builder configuration for consistency.
// This allows catching configuration errors before calling Build().
//
// Example:
//
//	builder := NewCertificateBuilder().WithType(CERT_KEY)
//	if err := builder.Validate(); err != nil {
//	    // Fix configuration before building
//	}
func (cb *CertificateBuilder) Validate() error {
	if cb == nil {
		return oops.Errorf("certificate builder is nil")
	}

	if err := cb.validateCertificateType(); err != nil {
		return err
	}

	if err := cb.validateKeyCertificateFields(); err != nil {
		return err
	}

	cb.warnPayloadConflict()
	return nil
}

// validateKeyCertificateFields checks that KEY certificate builders have
// the required key type fields set and are internally consistent.
func (cb *CertificateBuilder) validateKeyCertificateFields() error {
	if cb.certType != CERT_KEY {
		return nil
	}
	if cb.signingType == nil && cb.cryptoType == nil && !cb.payloadSet {
		return oops.Errorf("KEY certificates require either key types or explicit payload")
	}
	if cb.signingType != nil && cb.cryptoType == nil {
		return oops.Errorf("signing type set but crypto type not set")
	}
	if cb.cryptoType != nil && cb.signingType == nil {
		return oops.Errorf("crypto type set but signing type not set")
	}
	return nil
}

// warnPayloadConflict logs a warning when both an explicit payload and key types
// are set, since key types will be ignored.
func (cb *CertificateBuilder) warnPayloadConflict() {
	if cb.payloadSet && cb.signingType != nil {
		log.Warn("Both explicit payload and key types set - key types will be ignored")
	}
}

// validateCertificateType validates that the certificate type is valid.
func (cb *CertificateBuilder) validateCertificateType() error {
	if !isValidCertType(cb.certType) {
		return oops.Errorf("invalid certificate type: %d", cb.certType)
	}
	return nil
}

// isValidCertType checks if a certificate type is valid.
func isValidCertType(certType uint8) bool {
	switch certType {
	case CERT_NULL, CERT_HASHCASH, CERT_HIDDEN, CERT_SIGNED, CERT_MULTIPLE, CERT_KEY:
		return true
	default:
		return false
	}
}

// buildPayloadIfNeeded builds the payload from key types if not already set.
func (cb *CertificateBuilder) buildPayloadIfNeeded() error {
	// If payload is already set (via WithPayload), use it
	if cb.payloadSet {
		return nil
	}

	// If key types are set, build payload from them
	if cb.signingType != nil && cb.cryptoType != nil {
		cb.payload = cb.buildKeyTypePayload()
		return nil
	}

	// For KEY certificates without key types, require explicit payload
	if cb.certType == CERT_KEY && len(cb.payload) == 0 {
		return oops.Errorf("KEY certificates require either key types or explicit payload")
	}

	// For NULL and HIDDEN certificates, ensure empty payload per spec
	if cb.certType == CERT_NULL || cb.certType == CERT_HIDDEN {
		cb.payload = []byte{}
	}

	return nil
}

// buildKeyTypePayload builds a 4-byte payload from signing and crypto types.
func (cb *CertificateBuilder) buildKeyTypePayload() []byte {
	payload := make([]byte, 4)

	// Write signing key type (2 bytes, big endian)
	binary.BigEndian.PutUint16(payload[0:2], uint16(*cb.signingType))

	// Write crypto key type (2 bytes, big endian)
	binary.BigEndian.PutUint16(payload[2:4], uint16(*cb.cryptoType))

	return payload
}

// BuildKeyTypePayload is a convenience function to build key type payload without using builder.
// This is useful when you just need to generate the payload bytes.
//
// Parameters:
//   - signingType: The signing key type (must be non-negative and <= 65535)
//   - cryptoType: The crypto key type (must be non-negative and <= 65535)
//
// Returns:
//   - []byte: The 4-byte payload [signing_type][crypto_type]
//   - error: Non-nil if either type is negative or exceeds uint16 range
func BuildKeyTypePayload(signingType, cryptoType int) ([]byte, error) {
	if signingType < 0 {
		return nil, oops.Errorf("signing type cannot be negative: %d", signingType)
	}
	if cryptoType < 0 {
		return nil, oops.Errorf("crypto type cannot be negative: %d", cryptoType)
	}
	if signingType > 65535 {
		return nil, oops.Errorf("signing type exceeds uint16 range: %d", signingType)
	}
	if cryptoType > 65535 {
		return nil, oops.Errorf("crypto type exceeds uint16 range: %d", cryptoType)
	}
	payload := make([]byte, 4)
	binary.BigEndian.PutUint16(payload[0:2], uint16(signingType))
	binary.BigEndian.PutUint16(payload[2:4], uint16(cryptoType))
	return payload, nil
}
