package certificate

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCertificateBuilder_BasicUsage(t *testing.T) {
	builder := NewCertificateBuilder()
	builder, err := builder.WithType(CERT_NULL)
	require.NoError(t, err)

	cert, err := builder.Build()
	require.NoError(t, err)
	require.NotNil(t, cert)

	certType, _ := cert.Type()
	assert.Equal(t, CERT_NULL, certType)
}

func TestCertificateBuilder_WithKeyTypes(t *testing.T) {
	const signingType = 7 // Ed25519
	const cryptoType = 4  // X25519

	builder := NewCertificateBuilder()
	builder, err := builder.WithKeyTypes(signingType, cryptoType)
	require.NoError(t, err)

	cert, err := builder.Build()
	require.NoError(t, err)
	require.NotNil(t, cert)

	// Verify certificate type is KEY
	certType, err := cert.Type()
	require.NoError(t, err)
	assert.Equal(t, CERT_KEY, certType)

	// Verify payload is 4 bytes
	payload, err := cert.Data()
	require.NoError(t, err)
	assert.Equal(t, 4, len(payload))

	// Verify payload contains correct key types
	assert.Equal(t, []byte{0x00, 0x07, 0x00, 0x04}, payload)
}

func TestCertificateBuilder_WithCustomPayload(t *testing.T) {
	customPayload := []byte{0x01, 0x02, 0x03, 0x04, 0x05}

	builder := NewCertificateBuilder()
	builder, err := builder.WithType(CERT_HASHCASH)
	require.NoError(t, err)
	builder = builder.WithPayload(customPayload)

	cert, err := builder.Build()
	require.NoError(t, err)
	require.NotNil(t, cert)

	certType, _ := cert.Type()
	assert.Equal(t, CERT_HASHCASH, certType)

	payload, err := cert.Data()
	require.NoError(t, err)
	assert.Equal(t, customPayload, payload)
}

func TestCertificateBuilder_FluentInterface(t *testing.T) {
	builder := NewCertificateBuilder()

	// Verify fluent interface returns builder and error
	builder2, err := builder.WithType(CERT_KEY)
	assert.NoError(t, err)
	assert.Equal(t, builder, builder2)

	builder3, err := builder.WithKeyTypes(7, 4)
	assert.NoError(t, err)
	assert.Equal(t, builder, builder3)

	builder4 := builder.WithPayload([]byte{0x01})
	assert.Equal(t, builder, builder4)
}

func TestCertificateBuilder_InvalidType(t *testing.T) {
	// Test eager validation in WithType
	builder := NewCertificateBuilder()
	_, err := builder.WithType(99) // Invalid type
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid certificate type")

	// Since setter failed, builder is still in valid NULL state
	// Build should succeed with the default NULL type
	cert, err := builder.Build()
	assert.NoError(t, err, "builder should still be valid with default NULL type")
	assert.NotNil(t, cert)

	certType, _ := cert.Type()
	assert.Equal(t, CERT_NULL, certType, "should have default NULL type")
}

func TestCertificateBuilder_KeyTypeOverridesPayload(t *testing.T) {
	// When both key types and custom payload are set, custom payload takes precedence
	builder := NewCertificateBuilder()
	builder, err := builder.WithKeyTypes(7, 4)
	require.NoError(t, err)
	builder = builder.WithPayload([]byte{0x01, 0x02}) // Override with custom payload

	cert, err := builder.Build()
	require.NoError(t, err)

	payload, _ := cert.Data()
	assert.Equal(t, 2, len(payload)) // Custom payload used, not key types
	assert.Equal(t, []byte{0x01, 0x02}, payload)
}

func TestCertificateBuilder_NullCertificate(t *testing.T) {
	cert, err := NewCertificateBuilder().Build()

	require.NoError(t, err)
	require.NotNil(t, cert)

	certType, _ := cert.Type()
	assert.Equal(t, CERT_NULL, certType)

	payload, _ := cert.Data()
	assert.Equal(t, 0, len(payload))
}

func TestBuildKeyTypePayload(t *testing.T) {
	tests := []struct {
		name        string
		signingType int
		cryptoType  int
		want        []byte
	}{
		{
			name:        "Ed25519_X25519",
			signingType: 7,
			cryptoType:  4,
			want:        []byte{0x00, 0x07, 0x00, 0x04},
		},
		{
			name:        "DSA_ElGamal",
			signingType: 0,
			cryptoType:  0,
			want:        []byte{0x00, 0x00, 0x00, 0x00},
		},
		{
			name:        "P256_P256",
			signingType: 1,
			cryptoType:  1,
			want:        []byte{0x00, 0x01, 0x00, 0x01},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload, err := BuildKeyTypePayload(tt.signingType, tt.cryptoType)
			require.NoError(t, err)
			assert.Equal(t, tt.want, payload)
			assert.Equal(t, 4, len(payload))
		})
	}
}

func TestCertificateBuilder_AllTypes(t *testing.T) {
	types := []uint8{
		CERT_NULL,
		CERT_HASHCASH,
		CERT_HIDDEN,
		CERT_SIGNED,
		CERT_MULTIPLE,
		CERT_KEY,
	}

	for _, certType := range types {
		t.Run(string(rune(certType)), func(t *testing.T) {
			var cert *Certificate
			var err error

			builder := NewCertificateBuilder()
			if certType == CERT_KEY {
				builder, err = builder.WithKeyTypes(7, 4)
				require.NoError(t, err)
				cert, err = builder.Build()
			} else if certType == CERT_NULL || certType == CERT_HIDDEN {
				builder, err = builder.WithType(certType)
				require.NoError(t, err)
				cert, err = builder.Build()
			} else if certType == CERT_SIGNED {
				builder, err = builder.WithType(certType)
				require.NoError(t, err)
				builder = builder.WithPayload(make([]byte, CERT_SIGNED_PAYLOAD_SHORT))
				cert, err = builder.Build()
			} else {
				builder, err = builder.WithType(certType)
				require.NoError(t, err)
				builder = builder.WithPayload([]byte{0x01})
				cert, err = builder.Build()
			}

			require.NoError(t, err)
			require.NotNil(t, cert)

			actualType, _ := cert.Type()
			assert.Equal(t, int(certType), actualType)
		})
	}
}

// Benchmark tests
func BenchmarkCertificateBuilder_Simple(b *testing.B) {
	for i := 0; i < b.N; i++ {
		builder := NewCertificateBuilder()
		builder, _ = builder.WithType(CERT_NULL)
		_, _ = builder.Build()
	}
}

func BenchmarkCertificateBuilder_WithKeyTypes(b *testing.B) {
	for i := 0; i < b.N; i++ {
		builder := NewCertificateBuilder()
		builder, _ = builder.WithKeyTypes(7, 4)
		_, _ = builder.Build()
	}
}

func BenchmarkBuildKeyTypePayload(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = BuildKeyTypePayload(7, 4)
	}
}

// Validation tests

func TestCertificateBuilder_Validate(t *testing.T) {
	t.Run("valid null certificate", func(t *testing.T) {
		builder := NewCertificateBuilder()
		err := builder.Validate()
		assert.NoError(t, err)
	})

	t.Run("valid key certificate with key types", func(t *testing.T) {
		builder := NewCertificateBuilder()
		builder, err := builder.WithKeyTypes(7, 4)
		require.NoError(t, err)
		err = builder.Validate()
		assert.NoError(t, err)
	})

	t.Run("valid key certificate with payload", func(t *testing.T) {
		builder := NewCertificateBuilder()
		builder, err := builder.WithType(CERT_KEY)
		require.NoError(t, err)
		builder = builder.WithPayload([]byte{0x00, 0x07, 0x00, 0x04})
		err = builder.Validate()
		assert.NoError(t, err)
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
		assert.Contains(t, err.Error(), "invalid certificate type")
	})

	t.Run("key certificate without key types or payload", func(t *testing.T) {
		builder := &CertificateBuilder{certType: CERT_KEY}
		err := builder.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "require either key types or explicit payload")
	})

	t.Run("signing type set but crypto type missing", func(t *testing.T) {
		signingType := 7
		builder := &CertificateBuilder{
			certType:    CERT_KEY,
			signingType: &signingType,
		}
		err := builder.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "crypto type not set")
	})

	t.Run("crypto type set but signing type missing", func(t *testing.T) {
		cryptoType := 4
		builder := &CertificateBuilder{
			certType:   CERT_KEY,
			cryptoType: &cryptoType,
		}
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
		// Create builder in invalid state by bypassing setters
		builder := &CertificateBuilder{certType: 99}
		cert, err := builder.Build()
		assert.Error(t, err)
		assert.Nil(t, cert)
		assert.Contains(t, err.Error(), "invalid builder configuration")
	})

	t.Run("build succeeds with valid configuration", func(t *testing.T) {
		builder := NewCertificateBuilder()
		builder, err := builder.WithKeyTypes(7, 4)
		require.NoError(t, err)
		cert, err := builder.Build()
		assert.NoError(t, err)
		assert.NotNil(t, cert)
	})
}

func TestCertificateBuilder_EarlyValidation(t *testing.T) {
	t.Run("invalid type caught immediately", func(t *testing.T) {
		builder := NewCertificateBuilder()
		_, err := builder.WithType(99)
		assert.Error(t, err, "WithType should return error immediately")
		assert.Contains(t, err.Error(), "invalid certificate type")
	})

	t.Run("invalid key types caught immediately", func(t *testing.T) {
		builder := NewCertificateBuilder()
		_, err := builder.WithKeyTypes(-1, 4)
		assert.Error(t, err, "WithKeyTypes should return error immediately")
		assert.Contains(t, err.Error(), "signing type cannot be negative")
	})
}

func TestCertificateBuilder_PayloadPrecedence(t *testing.T) {
	t.Run("explicit payload overrides key types", func(t *testing.T) {
		builder := NewCertificateBuilder()
		builder, err := builder.WithKeyTypes(7, 4)
		require.NoError(t, err)

		// Override with explicit payload
		customPayload := []byte{0xAA, 0xBB, 0xCC, 0xDD}
		builder = builder.WithPayload(customPayload)

		cert, err := builder.Build()
		require.NoError(t, err)

		payload, err := cert.Data()
		require.NoError(t, err)
		assert.Equal(t, customPayload, payload)
	})
}

func TestCertificateBuilder_RoundTrip(t *testing.T) {
	t.Run("null certificate", func(t *testing.T) {
		builder := NewCertificateBuilder()
		cert, err := builder.Build()
		require.NoError(t, err)

		bytes := cert.Bytes()

		parsed, _, err := ReadCertificate(bytes)
		require.NoError(t, err)
		assert.True(t, parsed.IsValid())

		parsedType, _ := parsed.Type()
		origType, _ := cert.Type()
		assert.Equal(t, origType, parsedType)
	})

	t.Run("key certificate", func(t *testing.T) {
		builder := NewCertificateBuilder()
		builder, err := builder.WithKeyTypes(7, 4)
		require.NoError(t, err)

		cert, err := builder.Build()
		require.NoError(t, err)

		bytes := cert.Bytes()

		parsed, _, err := ReadCertificate(bytes)
		require.NoError(t, err)
		assert.True(t, parsed.IsValid())

		parsedPayload, _ := parsed.Data()
		origPayload, _ := cert.Data()
		assert.Equal(t, origPayload, parsedPayload)
	})
}
