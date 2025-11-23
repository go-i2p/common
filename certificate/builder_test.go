package certificate

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCertificateBuilder_BasicUsage(t *testing.T) {
	cert, err := NewCertificateBuilder().
		WithType(CERT_NULL).
		Build()

	require.NoError(t, err)
	require.NotNil(t, cert)

	certType, _ := cert.Type()
	assert.Equal(t, CERT_NULL, certType)
}

func TestCertificateBuilder_WithKeyTypes(t *testing.T) {
	const signingType = 7 // Ed25519
	const cryptoType = 4  // X25519

	cert, err := NewCertificateBuilder().
		WithKeyTypes(signingType, cryptoType).
		Build()

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

	cert, err := NewCertificateBuilder().
		WithType(CERT_SIGNED).
		WithPayload(customPayload).
		Build()

	require.NoError(t, err)
	require.NotNil(t, cert)

	certType, _ := cert.Type()
	assert.Equal(t, CERT_SIGNED, certType)

	payload, err := cert.Data()
	require.NoError(t, err)
	assert.Equal(t, customPayload, payload)
}

func TestCertificateBuilder_FluentInterface(t *testing.T) {
	builder := NewCertificateBuilder()

	// Verify fluent interface returns builder
	assert.Equal(t, builder, builder.WithType(CERT_KEY))
	assert.Equal(t, builder, builder.WithKeyTypes(7, 4))
	assert.Equal(t, builder, builder.WithPayload([]byte{0x01}))
}

func TestCertificateBuilder_InvalidType(t *testing.T) {
	cert, err := NewCertificateBuilder().
		WithType(99). // Invalid type
		Build()

	assert.Error(t, err)
	assert.Nil(t, cert)
}

func TestCertificateBuilder_KeyTypeOverridesPayload(t *testing.T) {
	// When both key types and custom payload are set, key types take precedence
	cert, err := NewCertificateBuilder().
		WithKeyTypes(7, 4).
		Build()

	require.NoError(t, err)
	payload, _ := cert.Data()
	assert.Equal(t, 4, len(payload))
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
			payload := BuildKeyTypePayload(tt.signingType, tt.cryptoType)
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

			if certType == CERT_KEY {
				cert, err = NewCertificateBuilder().
					WithKeyTypes(7, 4).
					Build()
			} else if certType == CERT_NULL {
				cert, err = NewCertificateBuilder().
					WithType(certType).
					Build()
			} else {
				cert, err = NewCertificateBuilder().
					WithType(certType).
					WithPayload([]byte{0x01}).
					Build()
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
		_, _ = NewCertificateBuilder().
			WithType(CERT_NULL).
			Build()
	}
}

func BenchmarkCertificateBuilder_WithKeyTypes(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = NewCertificateBuilder().
			WithKeyTypes(7, 4).
			Build()
	}
}

func BenchmarkBuildKeyTypePayload(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = BuildKeyTypePayload(7, 4)
	}
}
