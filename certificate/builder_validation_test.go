package certificate

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Validation tests for builder.go — input validation, error paths

func TestCertificateBuilder_InvalidType(t *testing.T) {
	builder := NewCertificateBuilder()
	_, err := builder.WithType(99)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid certificate type")

	cert, err := builder.Build()
	assert.NoError(t, err, "builder should still be valid with default NULL type")
	certType, _ := cert.Type()
	assert.Equal(t, CERT_NULL, certType)
}

func TestCertificateBuilder_Validate(t *testing.T) {
	t.Run("valid null certificate", func(t *testing.T) {
		builder := NewCertificateBuilder()
		assert.NoError(t, builder.Validate())
	})

	t.Run("valid key certificate with key types", func(t *testing.T) {
		builder := NewCertificateBuilder()
		builder, _ = builder.WithKeyTypes(7, 4)
		assert.NoError(t, builder.Validate())
	})

	t.Run("valid key certificate with payload", func(t *testing.T) {
		builder := NewCertificateBuilder()
		builder, _ = builder.WithType(CERT_KEY)
		builder = builder.WithPayload([]byte{0x00, 0x07, 0x00, 0x04})
		assert.NoError(t, builder.Validate())
	})

	t.Run("nil builder", func(t *testing.T) {
		var builder *CertificateBuilder
		err := builder.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "nil")
	})

	t.Run("invalid certificate type", func(t *testing.T) {
		builder := &CertificateBuilder{certType: 99}
		err := builder.Validate()
		assert.Error(t, err)
	})

	t.Run("key certificate without key types or payload", func(t *testing.T) {
		builder := &CertificateBuilder{certType: CERT_KEY}
		err := builder.Validate()
		assert.Error(t, err)
	})

	t.Run("signing type set but crypto type missing", func(t *testing.T) {
		signingType := 7
		builder := &CertificateBuilder{certType: CERT_KEY, signingType: &signingType}
		err := builder.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "crypto type not set")
	})

	t.Run("crypto type set but signing type missing", func(t *testing.T) {
		cryptoType := 4
		builder := &CertificateBuilder{certType: CERT_KEY, cryptoType: &cryptoType}
		err := builder.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "signing type not set")
	})
}

func TestCertificateBuilder_WithType_Validation(t *testing.T) {
	tests := []struct {
		name      string
		certType  uint8
		wantError bool
	}{
		{"CERT_NULL", CERT_NULL, false},
		{"CERT_HASHCASH", CERT_HASHCASH, false},
		{"CERT_HIDDEN", CERT_HIDDEN, false},
		{"CERT_SIGNED", CERT_SIGNED, false},
		{"CERT_MULTIPLE", CERT_MULTIPLE, false},
		{"CERT_KEY", CERT_KEY, false},
		{"invalid type 99", 99, true},
		{"invalid type 255", 255, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder := NewCertificateBuilder()
			_, err := builder.WithType(tt.certType)
			if tt.wantError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestCertificateBuilder_WithKeyTypes_Validation(t *testing.T) {
	tests := []struct {
		name        string
		signingType int
		cryptoType  int
		wantError   bool
	}{
		{"valid Ed25519/X25519", 7, 4, false},
		{"valid DSA/ElGamal", 0, 0, false},
		{"negative signing type", -1, 4, true},
		{"negative crypto type", 7, -1, true},
		{"both negative", -1, -1, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder := NewCertificateBuilder()
			_, err := builder.WithKeyTypes(tt.signingType, tt.cryptoType)
			if tt.wantError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestCertificateBuilder_Build_Validation(t *testing.T) {
	t.Run("build catches validation errors", func(t *testing.T) {
		builder := &CertificateBuilder{certType: 99}
		cert, err := builder.Build()
		assert.Error(t, err)
		assert.Nil(t, cert)
	})

	t.Run("build succeeds with valid configuration", func(t *testing.T) {
		builder := NewCertificateBuilder()
		builder, _ = builder.WithKeyTypes(7, 4)
		cert, err := builder.Build()
		assert.NoError(t, err)
		assert.NotNil(t, cert)
	})
}

func TestCertificateBuilder_EarlyValidation(t *testing.T) {
	t.Run("invalid type caught immediately", func(t *testing.T) {
		builder := NewCertificateBuilder()
		_, err := builder.WithType(99)
		assert.Error(t, err)
	})

	t.Run("invalid key types caught immediately", func(t *testing.T) {
		builder := NewCertificateBuilder()
		_, err := builder.WithKeyTypes(-1, 4)
		assert.Error(t, err)
	})
}
