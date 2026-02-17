// Package certificate implements the I2P Certificate common data structure according to specification version 0.9.67.
//
// Certificates are used throughout I2P to provide cryptographic metadata about keys,
// signatures, and other security parameters. They support multiple certificate types
// and provide flexible payload storage.
//
// # Overview
//
// The Certificate structure consists of:
//
//   - Type: Certificate type identifier (NULL, HASHCASH, HIDDEN, SIGNED, MULTIPLE, KEY)
//   - Length: Payload length in bytes (0-65535)
//   - Payload: Variable-length data specific to the certificate type
//
// # Certificate Types
//
// The package supports six certificate types:
//
//   - CERT_NULL (0): No certificate (legacy)
//   - CERT_HASHCASH (1): HashCash proof-of-work
//   - CERT_HIDDEN (2): Hidden service certificate
//   - CERT_SIGNED (3): Signed certificate
//   - CERT_MULTIPLE (4): Multiple certificates
//   - CERT_KEY (5): Key certificate with signing/crypto type info
//
// # Safe Constructors
//
// The package provides validated construction through the builder pattern:
//
//	// Create a KEY certificate with validation
//	builder := certificate.NewCertificateBuilder()
//	builder, err := builder.WithType(certificate.CERT_KEY)
//	if err != nil {
//	    return err
//	}
//	builder, err = builder.WithKeyTypes(7, 4)  // Ed25519/X25519
//	if err != nil {
//	    return err
//	}
//	cert, err := builder.Build()
//	if err != nil {
//	    return err
//	}
//
//	// Create a NULL certificate (no payload)
//	cert, err := certificate.NewCertificateBuilder().
//	    WithType(certificate.CERT_NULL).
//	    Build()
//
// # Parsing from Bytes
//
// Certificates can be safely parsed from byte streams:
//
//	cert, remainder, err := certificate.ReadCertificate(data)
//	if err != nil {
//	    return err
//	}
//	if !cert.IsValid() {
//	    return errors.New("invalid certificate")
//	}
//
// # Validation
//
// All certificates support validation to ensure proper initialization:
//
//	// Boolean validation check
//	if !cert.IsValid() {
//	    return errors.New("invalid certificate")
//	}
//
//	// Builder-level validation (before Build)
//	if err := builder.Validate(); err != nil {
//	    // Fix configuration before building
//	}
//
// # Accessing Certificate Data
//
// Certificate fields can be safely accessed with error handling:
//
//	certType, err := cert.Type()
//	if err != nil {
//	    return err
//	}
//
//	length, err := cert.Length()
//	if err != nil {
//	    return err
//	}
//
//	payload, err := cert.Data()
//	if err != nil {
//	    return err
//	}
//
// # Builder Pattern
//
// The CertificateBuilder provides fluent API with early validation:
//
//	// Builder validates configuration at each step
//	builder := NewCertificateBuilder()
//	builder, err := builder.WithType(CERT_KEY)
//	if err != nil {
//	    return err  // Invalid type rejected immediately
//	}
//
//	// Validate before building
//	if err := builder.Validate(); err != nil {
//	    // Fix configuration issues
//	}
//
//	cert, err := builder.Build()
//
// # Best Practices
//
//   - Use the builder pattern for creating new certificates
//   - Always validate certificates after parsing from bytes
//   - Use safe accessor methods (Type(), Length(), Data()) with error checking
//   - Prefer KEY certificates for modern cryptographic parameters
//
// # Specification
//
// Reference: https://geti2p.net/spec/common-structures#certificate
//
// This implementation follows I2P specification version 0.9.67 and provides
// comprehensive validation and error handling for all certificate operations.
package certificate
