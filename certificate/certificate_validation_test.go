package certificate

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Validation tests for certificate.go and certificate_struct.go
// — error paths, boundary conditions, type validation, payload validation

func TestCertificateLengthErrWhenTooShort(t *testing.T) {
	_, _, err := ReadCertificate([]byte{0x03, 0x01})
	require.NotNil(t, err)
	assert.Equal(t, "error parsing certificate: certificate is too short", err.Error())
}

func TestCertificateLengthErrWhenDataTooShort(t *testing.T) {
	_, _, err := ReadCertificate([]byte{0x03, 0x00, 0x02, 0xff})
	require.NotNil(t, err)
	assert.Equal(t, "certificate parsing warning: certificate data is shorter than specified by length", err.Error())
}

func TestReadCertificateWithCorrectData(t *testing.T) {
	cert, remainder, err := ReadCertificate([]byte{0x00, 0x00, 0x02, 0xff, 0xff})
	assert.Equal(t, 5, cert.length())
	assert.Equal(t, 0, len(remainder))
	assert.Nil(t, err)
}

func TestReadCertificateWithDataTooShort(t *testing.T) {
	data := []byte{0x00, 0x00, 0x02, 0xff}
	cert, remainder, err := ReadCertificate(data)
	assert.Nil(t, cert)
	assert.Equal(t, data, remainder)
	require.NotNil(t, err)
}

func TestReadCertificateWithRemainder(t *testing.T) {
	cert, remainder, err := ReadCertificate([]byte{0x00, 0x00, 0x02, 0xff, 0xff, 0x01})
	assert.Equal(t, 5, cert.length())
	assert.Equal(t, 1, len(remainder))
	assert.Nil(t, err)
}

func TestReadCertificateWithInvalidLength(t *testing.T) {
	data := []byte{0x00, 0x00}
	cert, remainder, err := ReadCertificate(data)
	assert.Nil(t, cert)
	assert.Equal(t, data, remainder)
	require.NotNil(t, err)
	assert.Equal(t, "error parsing certificate: certificate is too short", err.Error())
}

func TestCertificateHandlesOneByte(t *testing.T) {
	data := []byte{0x03}
	cert, remainder, err := ReadCertificate(data)
	require.NotNil(t, err)
	assert.Nil(t, cert)
	assert.Equal(t, data, remainder)
}

func TestCertificateHandlesZeroBytes(t *testing.T) {
	_, _, err := ReadCertificate([]byte{})
	require.NotNil(t, err)
	assert.Equal(t, "error parsing certificate: certificate is empty", err.Error())
}

func TestReadCertificateErrorHandling(t *testing.T) {
	t.Run("too short returns nil certificate", func(t *testing.T) {
		cert, remainder, err := ReadCertificate([]byte{0x00})
		require.NotNil(t, err)
		assert.Nil(t, cert)
		assert.Equal(t, []byte{0x00}, remainder)
	})

	t.Run("empty input returns nil certificate", func(t *testing.T) {
		cert, _, err := ReadCertificate([]byte{})
		require.NotNil(t, err)
		assert.Nil(t, cert)
	})

	t.Run("valid certificate returns non-nil", func(t *testing.T) {
		cert, remainder, err := ReadCertificate([]byte{CERT_NULL, 0x00, 0x00})
		assert.Nil(t, err)
		assert.NotNil(t, cert)
		assert.True(t, cert.IsValid())
		assert.Equal(t, 0, len(remainder))
	})
}

func TestErrorPathLengthFieldIs2Bytes(t *testing.T) {
	t.Run("empty input returns error", func(t *testing.T) {
		cert, _, err := ReadCertificate([]byte{})
		require.Error(t, err)
		assert.Nil(t, cert)
	})

	t.Run("1-byte input returns error", func(t *testing.T) {
		cert, _, err := ReadCertificate([]byte{0x05})
		require.Error(t, err)
		assert.Nil(t, cert)
	})

	t.Run("2-byte input returns error", func(t *testing.T) {
		cert, _, err := ReadCertificate([]byte{0x05, 0x00})
		require.Error(t, err)
		assert.Nil(t, cert)
	})
}

func TestBuildKeyTypePayloadValidation(t *testing.T) {
	t.Run("negative signing type rejected", func(t *testing.T) {
		_, err := BuildKeyTypePayload(-1, 4)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "signing type cannot be negative")
	})

	t.Run("negative crypto type rejected", func(t *testing.T) {
		_, err := BuildKeyTypePayload(7, -1)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "crypto type cannot be negative")
	})

	t.Run("signing type exceeds uint16 range", func(t *testing.T) {
		_, err := BuildKeyTypePayload(65536, 4)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "exceeds uint16 range")
	})

	t.Run("crypto type exceeds uint16 range", func(t *testing.T) {
		_, err := BuildKeyTypePayload(7, 65536)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "exceeds uint16 range")
	})

	t.Run("zero values valid", func(t *testing.T) {
		payload, err := BuildKeyTypePayload(0, 0)
		require.NoError(t, err)
		assert.Equal(t, []byte{0x00, 0x00, 0x00, 0x00}, payload)
	})

	t.Run("max uint16 values valid", func(t *testing.T) {
		payload, err := BuildKeyTypePayload(65535, 65535)
		require.NoError(t, err)
		assert.Equal(t, []byte{0xFF, 0xFF, 0xFF, 0xFF}, payload)
	})

	t.Run("valid Ed25519/X25519", func(t *testing.T) {
		payload, err := BuildKeyTypePayload(7, 4)
		require.NoError(t, err)
		assert.Equal(t, []byte{0x00, 0x07, 0x00, 0x04}, payload)
	})
}

func TestTypeSpecificPayloadValidation(t *testing.T) {
	t.Run("NULL cert with payload logs warning but parses", func(t *testing.T) {
		cert, _, err := ReadCertificate([]byte{CERT_NULL, 0x00, 0x02, 0xAA, 0xBB})
		require.NoError(t, err)
		certType, _ := cert.Type()
		assert.Equal(t, CERT_NULL, certType)
	})

	t.Run("KEY cert with valid payload parses", func(t *testing.T) {
		cert, _, err := ReadCertificate([]byte{CERT_KEY, 0x00, 0x04, 0x00, 0x07, 0x00, 0x04})
		require.NoError(t, err)
		certType, _ := cert.Type()
		assert.Equal(t, CERT_KEY, certType)
	})

	t.Run("KEY cert with insufficient payload logs warning", func(t *testing.T) {
		cert, _, err := ReadCertificate([]byte{CERT_KEY, 0x00, 0x02, 0x00, 0x07})
		require.NoError(t, err)
		require.NotNil(t, cert)
	})
}

func TestTypeValidationAsymmetry(t *testing.T) {
	t.Run("creation rejects type 6", func(t *testing.T) {
		_, err := NewCertificateWithType(6, []byte{})
		require.Error(t, err)
	})

	t.Run("parsing accepts type 6 from bytes", func(t *testing.T) {
		cert, _, err := ReadCertificate([]byte{6, 0x00, 0x00})
		require.NoError(t, err)
		certType, _ := cert.Type()
		assert.Equal(t, 6, certType)
	})

	t.Run("parsing accepts type 255 from bytes", func(t *testing.T) {
		cert, _, err := ReadCertificate([]byte{255, 0x00, 0x00})
		require.NoError(t, err)
		certType, _ := cert.Type()
		assert.Equal(t, 255, certType)
	})
}

func TestTypeAsymmetry(t *testing.T) {
	t.Run("constructor rejects unknown types", func(t *testing.T) {
		for _, invalidType := range []uint8{6, 7, 100, 200, 255} {
			_, err := NewCertificateWithType(invalidType, []byte{})
			require.Error(t, err)
		}
	})

	t.Run("parser accepts any type byte 0-255", func(t *testing.T) {
		for _, typeVal := range []byte{0, 5, 6, 100, 255} {
			cert, _, err := ReadCertificate([]byte{typeVal, 0x00, 0x00})
			require.NoError(t, err)
			ct, _ := cert.Type()
			assert.Equal(t, int(typeVal), ct)
		}
	})
}

func TestSignedCertificatePayloadValidation(t *testing.T) {
	t.Run("constructor accepts 40-byte SIGNED payload", func(t *testing.T) {
		cert, err := NewCertificateWithType(CERT_SIGNED, make([]byte, CERT_SIGNED_PAYLOAD_SHORT))
		require.NoError(t, err)
		certLen, _ := cert.Length()
		assert.Equal(t, 40, certLen)
	})

	t.Run("constructor accepts 72-byte SIGNED payload", func(t *testing.T) {
		cert, err := NewCertificateWithType(CERT_SIGNED, make([]byte, CERT_SIGNED_PAYLOAD_LONG))
		require.NoError(t, err)
		certLen, _ := cert.Length()
		assert.Equal(t, 72, certLen)
	})

	t.Run("constructor rejects 0-byte SIGNED payload", func(t *testing.T) {
		_, err := NewCertificateWithType(CERT_SIGNED, []byte{})
		require.Error(t, err)
	})

	t.Run("constructor rejects 39-byte SIGNED payload", func(t *testing.T) {
		_, err := NewCertificateWithType(CERT_SIGNED, make([]byte, 39))
		require.Error(t, err)
	})

	t.Run("constructor rejects 41-byte SIGNED payload", func(t *testing.T) {
		_, err := NewCertificateWithType(CERT_SIGNED, make([]byte, 41))
		require.Error(t, err)
	})

	t.Run("ReadCertificate still accepts non-conforming SIGNED from wire", func(t *testing.T) {
		cert, _, err := ReadCertificate([]byte{CERT_SIGNED, 0x00, 0x02, 0xAA, 0xBB})
		require.NoError(t, err)
		certType, _ := cert.Type()
		assert.Equal(t, CERT_SIGNED, certType)
	})
}

func TestHiddenCertificatePayloadValidation(t *testing.T) {
	t.Run("constructor accepts empty HIDDEN payload", func(t *testing.T) {
		cert, err := NewCertificateWithType(CERT_HIDDEN, []byte{})
		require.NoError(t, err)
		require.NotNil(t, cert)
	})

	t.Run("constructor rejects non-empty HIDDEN payload", func(t *testing.T) {
		_, err := NewCertificateWithType(CERT_HIDDEN, []byte{0x01})
		require.Error(t, err)
	})
}

func TestKeyCertificatePayloadMinimum(t *testing.T) {
	t.Run("KEY cert with exactly 4 bytes payload accepted", func(t *testing.T) {
		_, err := NewCertificateWithType(CERT_KEY, []byte{0x00, 0x07, 0x00, 0x04})
		require.NoError(t, err)
	})

	t.Run("KEY cert with excess key data accepted", func(t *testing.T) {
		payload := make([]byte, 100)
		payload[1] = 0x07
		payload[3] = 0x04
		_, err := NewCertificateWithType(CERT_KEY, payload)
		require.NoError(t, err)
	})
}

func TestDataAliasingDefensiveCopy(t *testing.T) {
	t.Run("mutating source bytes after ReadCertificate does not corrupt certificate", func(t *testing.T) {
		src := []byte{CERT_KEY, 0x00, 0x04, 0x00, 0x07, 0x00, 0x04}
		cert, _, err := ReadCertificate(src)
		require.NoError(t, err)

		origType, _ := cert.Type()
		origLen, _ := cert.Length()
		origData, _ := cert.Data()
		origDataCopy := make([]byte, len(origData))
		copy(origDataCopy, origData)

		for i := range src {
			src[i] = 0xFF
		}

		newType, _ := cert.Type()
		assert.Equal(t, origType, newType)
		newLen, _ := cert.Length()
		assert.Equal(t, origLen, newLen)
		newData, _ := cert.Data()
		assert.Equal(t, origDataCopy, newData)
	})

	t.Run("mutating source bytes does not affect NULL certificate", func(t *testing.T) {
		src := []byte{CERT_NULL, 0x00, 0x00}
		cert, _, _ := ReadCertificate(src)
		src[0] = 0xFF
		newType, _ := cert.Type()
		assert.Equal(t, CERT_NULL, newType)
	})
}

func TestReadCertificateWithoutNormalize(t *testing.T) {
	t.Run("valid cert parses without error", func(t *testing.T) {
		cert, remainder, err := ReadCertificate([]byte{CERT_NULL, 0x00, 0x00})
		require.NoError(t, err)
		require.NotNil(t, cert)
		assert.Equal(t, 0, len(remainder))
	})

	t.Run("cert with excess data parses correctly", func(t *testing.T) {
		cert, remainder, err := ReadCertificate([]byte{CERT_SIGNED, 0x00, 0x02, 0xAA, 0xBB, 0xCC, 0xDD})
		require.NoError(t, err)
		require.NotNil(t, cert)
		assert.Equal(t, []byte{0xCC, 0xDD}, remainder)
	})

	t.Run("short data returns error", func(t *testing.T) {
		cert, _, err := ReadCertificate([]byte{CERT_NULL, 0x00, 0x05, 0xAA})
		require.Error(t, err)
		assert.Nil(t, cert)
	})
}

func TestCertificateAccessorsWithInvalidCertificate(t *testing.T) {
	cert, _, err := ReadCertificate([]byte{0x00})
	assert.NotNil(t, err)
	assert.Nil(t, cert)
}

// Fuzz test

func FuzzReadCertificate(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x00})
	f.Add([]byte{0x00, 0x00})
	f.Add([]byte{0x00, 0x00, 0x00})
	f.Add([]byte{0x05, 0x00, 0x04, 0x00, 0x07, 0x00, 0x04})
	f.Add([]byte{0x00, 0x00, 0x01, 0xFF})
	f.Add([]byte{0xFF, 0xFF, 0xFF})
	f.Add([]byte{0x03, 0x00, 0x28})

	f.Fuzz(func(t *testing.T, data []byte) {
		cert, remainder, err := ReadCertificate(data)
		if err != nil {
			assert.Nil(t, cert)
			assert.Equal(t, data, remainder)
			return
		}
		require.NotNil(t, cert)
		assert.True(t, cert.IsValid())
	})
}

// Benchmarks

func BenchmarkReadCertificate(b *testing.B) {
	b.Run("NULL_certificate", func(b *testing.B) {
		data := []byte{CERT_NULL, 0x00, 0x00}
		for i := 0; i < b.N; i++ {
			ReadCertificate(data)
		}
	})

	b.Run("KEY_certificate", func(b *testing.B) {
		data := []byte{CERT_KEY, 0x00, 0x04, 0x00, 0x07, 0x00, 0x04}
		for i := 0; i < b.N; i++ {
			ReadCertificate(data)
		}
	})

	b.Run("large_payload", func(b *testing.B) {
		payload := make([]byte, 1000)
		data := append([]byte{CERT_KEY, 0x03, 0xE8}, payload...)
		for i := 0; i < b.N; i++ {
			ReadCertificate(data)
		}
	})
}
