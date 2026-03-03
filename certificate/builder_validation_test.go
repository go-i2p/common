package certificate

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
		builder, _ = builder.WithPayload([]byte{0x00, 0x07, 0x00, 0x04})
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

func TestWithKeyTypes_UpperBoundValidation(t *testing.T) {
	t.Run("signing type 65536 rejected", func(t *testing.T) {
		builder := NewCertificateBuilder()
		_, err := builder.WithKeyTypes(65536, 4)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "exceeds uint16 range")
	})

	t.Run("crypto type 65536 rejected", func(t *testing.T) {
		builder := NewCertificateBuilder()
		_, err := builder.WithKeyTypes(7, 65536)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "exceeds uint16 range")
	})

	t.Run("both types 65536 rejected", func(t *testing.T) {
		builder := NewCertificateBuilder()
		_, err := builder.WithKeyTypes(65536, 65536)
		require.Error(t, err)
	})

	t.Run("signing type max uint16 (65535) accepted", func(t *testing.T) {
		builder := NewCertificateBuilder()
		_, err := builder.WithKeyTypes(65535, 4)
		require.NoError(t, err)
	})

	t.Run("crypto type max uint16 (65535) accepted", func(t *testing.T) {
		builder := NewCertificateBuilder()
		_, err := builder.WithKeyTypes(7, 65535)
		require.NoError(t, err)
	})

	t.Run("large overflow value rejected", func(t *testing.T) {
		builder := NewCertificateBuilder()
		_, err := builder.WithKeyTypes(100000, 4)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "exceeds uint16 range")
	})

	t.Run("WithKeyTypes matches BuildKeyTypePayload validation", func(t *testing.T) {
		builder := NewCertificateBuilder()
		_, builderErr := builder.WithKeyTypes(65536, 4)
		_, funcErr := BuildKeyTypePayload(65536, 4)
		assert.Error(t, builderErr)
		assert.Error(t, funcErr)

		builder2 := NewCertificateBuilder()
		_, builderErr2 := builder2.WithKeyTypes(65535, 65535)
		_, funcErr2 := BuildKeyTypePayload(65535, 65535)
		assert.NoError(t, builderErr2)
		assert.NoError(t, funcErr2)
	})
}

func TestWithPayload_ReturnsError(t *testing.T) {
	t.Run("oversized payload rejected", func(t *testing.T) {
		builder := NewCertificateBuilder()
		_, err := builder.WithPayload(make([]byte, CERT_MAX_PAYLOAD_SIZE+1))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "payload too long")
	})

	t.Run("max size payload accepted", func(t *testing.T) {
		builder := NewCertificateBuilder()
		_, err := builder.WithPayload(make([]byte, CERT_MAX_PAYLOAD_SIZE))
		require.NoError(t, err)
	})

	t.Run("nil payload accepted", func(t *testing.T) {
		builder := NewCertificateBuilder()
		_, err := builder.WithPayload(nil)
		require.NoError(t, err)
	})

	t.Run("empty payload accepted", func(t *testing.T) {
		builder := NewCertificateBuilder()
		_, err := builder.WithPayload([]byte{})
		require.NoError(t, err)
	})
}

func TestBuilderRetainsPreviousStateOnError(t *testing.T) {
	t.Run("WithType error retains previous type", func(t *testing.T) {
		builder := NewCertificateBuilder()
		// Set a valid type first
		builder, err := builder.WithKeyTypes(7, 4)
		require.NoError(t, err)

		// Attempt invalid type — should error but keep CERT_KEY
		_, err = builder.WithType(99)
		assert.Error(t, err)

		// Builder should still produce CERT_KEY certificate
		cert, err := builder.Build()
		require.NoError(t, err)
		certType, _ := cert.Type()
		assert.Equal(t, CERT_KEY, certType)
	})

	t.Run("WithKeyTypes error retains previous key types", func(t *testing.T) {
		builder := NewCertificateBuilder()
		builder, err := builder.WithKeyTypes(7, 4)
		require.NoError(t, err)

		// Attempt negative signing type — should error but keep previous key types
		_, err = builder.WithKeyTypes(-1, 0)
		assert.Error(t, err)

		cert, err := builder.Build()
		require.NoError(t, err)
		payload, _ := cert.Data()
		assert.Equal(t, []byte{0x00, 0x07, 0x00, 0x04}, payload,
			"previous key types should be retained after error")
	})

	t.Run("WithPayload error retains previous payload", func(t *testing.T) {
		builder := NewCertificateBuilder()
		builder, _ = builder.WithType(CERT_HASHCASH)
		originalPayload := []byte("1:20:060408:adam@cypherspace.org::McMybZIhxKXu57jd:ckvi")
		builder, err := builder.WithPayload(originalPayload)
		require.NoError(t, err)

		// Attempt oversized payload — should error but keep original
		_, err = builder.WithPayload(make([]byte, CERT_MAX_PAYLOAD_SIZE+1))
		assert.Error(t, err)

		cert, err := builder.Build()
		require.NoError(t, err)
		data, _ := cert.Data()
		assert.Equal(t, originalPayload, data,
			"previous payload should be retained after error")
	})
}
