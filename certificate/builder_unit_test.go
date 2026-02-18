package certificate

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Unit tests for builder.go — CertificateBuilder

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
	builder := NewCertificateBuilder()
	builder, err := builder.WithKeyTypes(7, 4)
	require.NoError(t, err)

	cert, err := builder.Build()
	require.NoError(t, err)

	certType, _ := cert.Type()
	assert.Equal(t, CERT_KEY, certType)

	payload, _ := cert.Data()
	assert.Equal(t, 4, len(payload))
	assert.Equal(t, []byte{0x00, 0x07, 0x00, 0x04}, payload)
}

func TestCertificateBuilder_WithCustomPayload(t *testing.T) {
	customPayload := []byte{0x01, 0x02, 0x03, 0x04, 0x05}

	builder := NewCertificateBuilder()
	builder, _ = builder.WithType(CERT_HASHCASH)
	builder = builder.WithPayload(customPayload)

	cert, err := builder.Build()
	require.NoError(t, err)

	certType, _ := cert.Type()
	assert.Equal(t, CERT_HASHCASH, certType)

	payload, _ := cert.Data()
	assert.Equal(t, customPayload, payload)
}

func TestCertificateBuilder_FluentInterface(t *testing.T) {
	builder := NewCertificateBuilder()

	builder2, err := builder.WithType(CERT_KEY)
	assert.NoError(t, err)
	assert.Equal(t, builder, builder2)

	builder3, err := builder.WithKeyTypes(7, 4)
	assert.NoError(t, err)
	assert.Equal(t, builder, builder3)

	builder4 := builder.WithPayload([]byte{0x01})
	assert.Equal(t, builder, builder4)
}

func TestCertificateBuilder_NullCertificate(t *testing.T) {
	cert, err := NewCertificateBuilder().Build()
	require.NoError(t, err)

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
		{"Ed25519_X25519", 7, 4, []byte{0x00, 0x07, 0x00, 0x04}},
		{"DSA_ElGamal", 0, 0, []byte{0x00, 0x00, 0x00, 0x00}},
		{"P256_P256", 1, 1, []byte{0x00, 0x01, 0x00, 0x01}},
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
	types := []uint8{CERT_NULL, CERT_HASHCASH, CERT_HIDDEN, CERT_SIGNED, CERT_MULTIPLE, CERT_KEY}

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
			actualType, _ := cert.Type()
			assert.Equal(t, int(certType), actualType)
		})
	}
}

func TestCertificateBuilder_KeyTypeOverridesPayload(t *testing.T) {
	builder := NewCertificateBuilder()
	builder, _ = builder.WithKeyTypes(7, 4)
	builder = builder.WithPayload([]byte{0x01, 0x02})

	cert, err := builder.Build()
	require.NoError(t, err)

	payload, _ := cert.Data()
	assert.Equal(t, []byte{0x01, 0x02}, payload)
}

func TestCertificateBuilder_PayloadPrecedence(t *testing.T) {
	builder := NewCertificateBuilder()
	builder, _ = builder.WithKeyTypes(7, 4)
	builder = builder.WithPayload([]byte{0xAA, 0xBB, 0xCC, 0xDD})

	cert, err := builder.Build()
	require.NoError(t, err)

	payload, _ := cert.Data()
	assert.Equal(t, []byte{0xAA, 0xBB, 0xCC, 0xDD}, payload)
}

func TestCertificateBuilder_RoundTrip(t *testing.T) {
	t.Run("null certificate", func(t *testing.T) {
		cert, err := NewCertificateBuilder().Build()
		require.NoError(t, err)

		parsed, _, err := ReadCertificate(cert.Bytes())
		require.NoError(t, err)
		assert.True(t, parsed.IsValid())

		parsedType, _ := parsed.Type()
		origType, _ := cert.Type()
		assert.Equal(t, origType, parsedType)
	})

	t.Run("key certificate", func(t *testing.T) {
		builder := NewCertificateBuilder()
		builder, _ = builder.WithKeyTypes(7, 4)
		cert, err := builder.Build()
		require.NoError(t, err)

		parsed, _, err := ReadCertificate(cert.Bytes())
		require.NoError(t, err)
		assert.True(t, parsed.IsValid())

		parsedPayload, _ := parsed.Data()
		origPayload, _ := cert.Data()
		assert.Equal(t, origPayload, parsedPayload)
	})
}

// Benchmarks

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
