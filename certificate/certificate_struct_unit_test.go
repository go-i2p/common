package certificate

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Unit tests for certificate_struct.go — Certificate struct methods, constructors

func TestCertificateTypeIsFirstByte(t *testing.T) {
	assert := assert.New(t)

	bytes := []byte{0x03, 0x00, 0x00}
	certificate, _, _ := ReadCertificate(bytes)
	cert_type, typeErr := certificate.Type()
	assert.Nil(typeErr, "certificate.Type() should not error for valid type")
	assert.Equal(cert_type, 3, "certificate.Type() should be the first bytes in a certificate")
}

func TestCertificateLengthCorrect(t *testing.T) {
	assert := assert.New(t)

	bytes := []byte{0x03, 0x00, 0x02, 0xff, 0xff}
	certificate, _, _ := ReadCertificate(bytes)
	cert_len, lenErr := certificate.Length()
	assert.Nil(lenErr, "certificate.Length() should not error for valid length")
	assert.Equal(cert_len, 2, "certificate.Length() should return integer from second two bytes")
}

func TestCertificateDataWhenCorrectSize(t *testing.T) {
	assert := assert.New(t)

	bytes := []byte{0x03, 0x00, 0x01, 0xaa}
	certificate, _, _ := ReadCertificate(bytes)
	cert_data, dataErr := certificate.Data()
	assert.Nil(dataErr, "certificate.Data() returned error with valid data")
	cert_len := len(cert_data)
	assert.Equal(cert_len, 1, "certificate.Data() did not return indicated length when data was valid")
	assert.Equal(170, int(cert_data[0]), "certificate.Data() returned incorrect data")
}

func TestCertificateDataWhenTooLong(t *testing.T) {
	assert := assert.New(t)

	bytes := []byte{0x03, 0x00, 0x02, 0xff, 0xff, 0xaa, 0xaa}
	certificate, _, _ := ReadCertificate(bytes)
	cert_data, dataErr := certificate.Data()
	assert.Nil(dataErr, "certificate.Data() should not error for valid length")
	cert_len, lenErr := certificate.Length()
	assert.Nil(lenErr, "certificate.Length() should not error for valid length")
	assert.Equal(cert_len, 2, "certificate.Length() did not return indicated length when data was too long")
	if cert_data[0] != 0xff || cert_data[1] != 0xff {
		t.Fatal("certificate.Data() returned incorrect data when data was too long")
	}
}

func TestNewCertificateMinSize(t *testing.T) {
	t.Run("serialized length equals CERT_MIN_SIZE", func(t *testing.T) {
		cert := NewCertificate()
		b := cert.Bytes()
		require.NotNil(t, b)
		assert.Equal(t, CERT_MIN_SIZE, len(b),
			"NewCertificate().Bytes() must produce exactly %d bytes (1 type + 2 length)", CERT_MIN_SIZE)
	})

	t.Run("serialized bytes are all zero", func(t *testing.T) {
		cert := NewCertificate()
		b := cert.Bytes()
		assert.Equal(t, []byte{0x00, 0x00, 0x00}, b,
			"NULL certificate should serialize to [type=0, length=0x0000]")
	})

	t.Run("round trip through ReadCertificate", func(t *testing.T) {
		cert := NewCertificate()
		b := cert.Bytes()
		parsed, remainder, err := ReadCertificate(b)
		require.NoError(t, err)
		require.NotNil(t, parsed)
		assert.Equal(t, 0, len(remainder))

		certType, _ := parsed.Type()
		assert.Equal(t, CERT_NULL, certType)

		certLen, _ := parsed.Length()
		assert.Equal(t, 0, certLen)
	})

	t.Run("length field is 2 bytes", func(t *testing.T) {
		cert := NewCertificate()
		assert.Equal(t, 2, len(cert.len),
			"length field must be exactly 2 bytes per spec")
	})
}

func TestNewCertificateNullType(t *testing.T) {
	assert := assert.New(t)

	cert, err := NewCertificateWithType(CERT_NULL, []byte{})
	assert.Nil(err, "Expected no error when creating NULL certificate with empty payload")
	typ, typErr := cert.Type()
	assert.Nil(typErr)
	assert.Equal(CERT_NULL, typ)
	length, lenErr := cert.Length()
	assert.Nil(lenErr)
	assert.Equal(0, length)
	data, dataErr := cert.Data()
	assert.Nil(dataErr)
	assert.Equal(0, len(data))
}

func TestNewCertificateNullTypeWithPayload(t *testing.T) {
	assert := assert.New(t)

	_, err := NewCertificateWithType(CERT_NULL, []byte{0x00})
	assert.NotNil(err)
	assert.Equal("NULL certificates must have empty payload", err.Error())
}

func TestNewCertificateKeyType(t *testing.T) {
	assert := assert.New(t)

	payload := []byte{0x00, 0x01, 0x02, 0x03, 0x04}
	cert, err := NewCertificateWithType(CERT_KEY, payload)
	assert.Nil(err)
	typ, typErr := cert.Type()
	assert.Nil(typErr)
	assert.Equal(CERT_KEY, typ)
	length, lenErr := cert.Length()
	assert.Nil(lenErr)
	assert.Equal(len(payload), length)
	data, dataErr := cert.Data()
	assert.Nil(dataErr)
	assert.Equal(payload, data)
}

func TestNewCertificateInvalidType(t *testing.T) {
	assert := assert.New(t)

	_, err := NewCertificateWithType(6, []byte{})
	assert.NotNil(err)
	assert.Equal("invalid certificate type: 6", err.Error())
}

func TestNewCertificatePayloadTooLong(t *testing.T) {
	assert := assert.New(t)

	payload := make([]byte, 65536)
	_, err := NewCertificateWithType(CERT_KEY, payload)
	assert.NotNil(err)
	assert.Equal("payload too long: 65536 bytes", err.Error())
}

func TestCertificateBytesSerialization(t *testing.T) {
	assert := assert.New(t)

	payload := []byte{0xAA, 0xBB, 0xCC}
	cert, err := NewCertificateWithType(uint8(CERT_MULTIPLE), payload)
	assert.Nil(err)

	expectedBytes := []byte{byte(CERT_MULTIPLE), 0x00, byte(len(payload)), 0xAA, 0xBB, 0xCC}
	assert.Equal(expectedBytes, cert.Bytes())
}

func TestCertificateFieldsAfterCreation(t *testing.T) {
	assert := assert.New(t)

	payload := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	cert, err := NewCertificateWithType(uint8(CERT_MULTIPLE), payload)
	assert.Nil(err)

	typ, _ := cert.Type()
	assert.Equal(CERT_MULTIPLE, typ)
	length, _ := cert.Length()
	assert.Equal(len(payload), length)
	data, _ := cert.Data()
	assert.Equal(payload, data)
}

func TestCertificateWithZeroLengthPayload(t *testing.T) {
	cert, err := NewCertificateWithType(uint8(CERT_HASHCASH), []byte{})
	assert.Nil(t, err)

	typ, _ := cert.Type()
	assert.Equal(t, CERT_HASHCASH, typ)
	length, _ := cert.Length()
	assert.Equal(t, 0, length)
}

func TestCertificateIsValid(t *testing.T) {
	t.Run("nil certificate", func(t *testing.T) {
		var cert *Certificate
		assert.False(t, cert.IsValid())
	})

	t.Run("zero value certificate", func(t *testing.T) {
		var cert Certificate
		assert.False(t, cert.IsValid())
	})

	t.Run("valid NULL certificate", func(t *testing.T) {
		cert, _ := NewCertificateWithType(CERT_NULL, []byte{})
		assert.True(t, cert.IsValid())
	})

	t.Run("valid certificate with payload", func(t *testing.T) {
		cert, _ := NewCertificateWithType(CERT_KEY, []byte{0x01, 0x02, 0x03})
		assert.True(t, cert.IsValid())
	})
}

func TestNilReceiverSafety(t *testing.T) {
	var cert *Certificate

	t.Run("Bytes returns nil on nil receiver", func(t *testing.T) {
		assert.NotPanics(t, func() { assert.Nil(t, cert.Bytes()) })
	})
	t.Run("RawBytes returns nil on nil receiver", func(t *testing.T) {
		assert.NotPanics(t, func() { assert.Nil(t, cert.RawBytes()) })
	})
	t.Run("ExcessBytes returns nil on nil receiver", func(t *testing.T) {
		assert.NotPanics(t, func() { assert.Nil(t, cert.ExcessBytes()) })
	})
	t.Run("length returns 0 on nil receiver", func(t *testing.T) {
		assert.NotPanics(t, func() { assert.Equal(t, 0, cert.length()) })
	})
}

func TestZeroValueReceiverSafety(t *testing.T) {
	var cert Certificate

	t.Run("Bytes returns nil on zero-value receiver", func(t *testing.T) {
		assert.NotPanics(t, func() { assert.Nil(t, cert.Bytes()) })
	})
	t.Run("RawBytes returns nil on zero-value receiver", func(t *testing.T) {
		assert.NotPanics(t, func() { assert.Nil(t, cert.RawBytes()) })
	})
	t.Run("ExcessBytes returns nil on zero-value receiver", func(t *testing.T) {
		assert.NotPanics(t, func() { assert.Nil(t, cert.ExcessBytes()) })
	})
	t.Run("length returns 0 on zero-value receiver", func(t *testing.T) {
		assert.NotPanics(t, func() { assert.Equal(t, 0, cert.length()) })
	})
}

func TestZeroValueCertificateUnsafe(t *testing.T) {
	var cert Certificate
	assert.False(t, cert.IsValid())

	_, err := cert.Type()
	assert.NotNil(t, err)
	assert.Equal(t, "certificate is not initialized", err.Error())

	_, err = cert.Length()
	assert.NotNil(t, err)

	_, err = cert.Data()
	assert.NotNil(t, err)
}

func TestNilCertificateSafety(t *testing.T) {
	var cert *Certificate
	assert.False(t, cert.IsValid())

	assert.NotPanics(t, func() {
		_, _ = cert.Type()
		_, _ = cert.Length()
		_, _ = cert.Data()
	})
}

func TestBytesVsRawBytes(t *testing.T) {
	t.Run("identical when payload matches declared length", func(t *testing.T) {
		payload := []byte{0x00, 0x07, 0x00, 0x04}
		cert, _ := NewCertificateWithType(CERT_KEY, payload)
		assert.Equal(t, cert.Bytes(), cert.RawBytes())
	})

	t.Run("differ when payload has excess data", func(t *testing.T) {
		wireData := []byte{CERT_KEY, 0x00, 0x02, 0x00, 0x07, 0x00, 0x04}
		cert, _, _ := ReadCertificate(wireData)
		require.NotNil(t, cert)

		assert.Equal(t, CERT_MIN_SIZE+2, len(cert.Bytes()))
		assert.Equal(t, CERT_MIN_SIZE+4, len(cert.RawBytes()))
		assert.Greater(t, len(cert.RawBytes()), len(cert.Bytes()))
	})

	t.Run("both nil on invalid certificate", func(t *testing.T) {
		var cert Certificate
		assert.Nil(t, cert.Bytes())
		assert.Nil(t, cert.RawBytes())
	})
}

func TestCertificateExcessBytes(t *testing.T) {
	assert := assert.New(t)

	payload := []byte{0x01, 0x02}
	extraBytes := []byte{0x03, 0x04}
	certData := append(payload, extraBytes...)

	certBytes := append([]byte{byte(CERT_SIGNED)}, []byte{0x00, byte(len(payload))}...)
	certBytes = append(certBytes, certData...)

	cert, _, err := ReadCertificate(certBytes)
	assert.Nil(err)

	excess := cert.ExcessBytes()
	assert.Equal(extraBytes, excess)

	data, _ := cert.Data()
	assert.Equal(payload, data)
}

func TestLengthOptimized(t *testing.T) {
	t.Run("length equals CERT_MIN_SIZE for NULL cert", func(t *testing.T) {
		cert := NewCertificate()
		assert.Equal(t, CERT_MIN_SIZE, cert.length())
	})

	t.Run("length equals CERT_MIN_SIZE + payload for KEY cert", func(t *testing.T) {
		payload := []byte{0x00, 0x07, 0x00, 0x04}
		cert, _ := NewCertificateWithType(CERT_KEY, payload)
		assert.Equal(t, CERT_MIN_SIZE+len(payload), cert.length())
	})

	t.Run("length matches Bytes length", func(t *testing.T) {
		payload := make([]byte, CERT_SIGNED_PAYLOAD_SHORT)
		cert, _ := NewCertificateWithType(CERT_SIGNED, payload)
		assert.Equal(t, len(cert.Bytes()), cert.length())
	})

	t.Run("length on zero-value cert is 0", func(t *testing.T) {
		var cert Certificate
		assert.Equal(t, 0, cert.length())
	})

	t.Run("length on nil cert is 0", func(t *testing.T) {
		var cert *Certificate
		assert.Equal(t, 0, cert.length())
	})
}

func TestAllMethodsUsePointerReceivers(t *testing.T) {
	cert, err := NewCertificateWithType(CERT_KEY, []byte{0x00, 0x07, 0x00, 0x04})
	require.NoError(t, err)

	assert.NotPanics(t, func() {
		cert.Type()
		cert.Length()
		cert.Data()
		cert.Bytes()
		cert.RawBytes()
		cert.ExcessBytes()
		cert.length()
		cert.IsValid()
	})
}

func TestCertificateSerializationDeserialization(t *testing.T) {
	payload := []byte{0xAA, 0xBB, 0xCC}
	original, err := NewCertificateWithType(uint8(CERT_MULTIPLE), payload)
	require.NoError(t, err)

	serialized := original.Bytes()
	parsed, _, err := ReadCertificate(serialized)
	require.NoError(t, err)

	origType, _ := original.Type()
	parsedType, _ := parsed.Type()
	assert.Equal(t, origType, parsedType)

	origData, _ := original.Data()
	parsedData, _ := parsed.Data()
	assert.Equal(t, origData, parsedData)
}

func TestCertificateSerializationMaxPayload(t *testing.T) {
	payload := make([]byte, 65535)
	for i := range payload {
		payload[i] = byte(i % 256)
	}

	original, err := NewCertificateWithType(uint8(CERT_KEY), payload)
	require.NoError(t, err)

	serialized := original.Bytes()
	assert.Equal(t, 1+2+65535, len(serialized))

	parsed, _, err := ReadCertificate(serialized)
	require.NoError(t, err)

	origData, _ := original.Data()
	parsedData, _ := parsed.Data()
	assert.True(t, bytes.Equal(origData, parsedData))
}

func TestCertificateRoundTripWithIsValid(t *testing.T) {
	original, err := NewCertificateWithType(CERT_SIGNED, make([]byte, CERT_SIGNED_PAYLOAD_SHORT))
	require.NoError(t, err)
	assert.True(t, original.IsValid())

	serialized := original.Bytes()
	parsed, _, err := ReadCertificate(serialized)
	require.NoError(t, err)
	assert.True(t, parsed.IsValid())

	origType, _ := original.Type()
	parsedType, _ := parsed.Type()
	assert.Equal(t, origType, parsedType)
}

func TestNewCertificateHiddenType(t *testing.T) {
	_, err := NewCertificateWithType(uint8(CERT_HIDDEN), []byte{0x11, 0x22})
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "HIDDEN certificates must have empty payload")

	cert, err := NewCertificateWithType(uint8(CERT_HIDDEN), []byte{})
	assert.Nil(t, err)
	typ, _ := cert.Type()
	assert.Equal(t, CERT_HIDDEN, typ)
	length, _ := cert.Length()
	assert.Equal(t, 0, length)
}

func TestNewCertificateWithInvalidPayloadLength(t *testing.T) {
	_, err := NewCertificateWithType(CERT_KEY, make([]byte, 70000))
	assert.NotNil(t, err)
	assert.Equal(t, "payload too long: 70000 bytes", err.Error())
}

func TestGetSignatureTypeFromCertificate(t *testing.T) {
	t.Run("valid KEY cert extracts Ed25519", func(t *testing.T) {
		payload := []byte{0x00, 0x07, 0x00, 0x04}
		cert, _ := NewCertificateWithType(CERT_KEY, payload)
		sigType, err := GetSignatureTypeFromCertificate(*cert)
		require.NoError(t, err)
		assert.Equal(t, 7, sigType)
	})

	t.Run("valid KEY cert extracts DSA (type 0)", func(t *testing.T) {
		payload := []byte{0x00, 0x00, 0x00, 0x00}
		cert, _ := NewCertificateWithType(CERT_KEY, payload)
		sigType, err := GetSignatureTypeFromCertificate(*cert)
		require.NoError(t, err)
		assert.Equal(t, 0, sigType)
	})

	t.Run("non-KEY cert returns error", func(t *testing.T) {
		cert, _ := NewCertificateWithType(CERT_NULL, []byte{})
		_, err := GetSignatureTypeFromCertificate(*cert)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unexpected certificate type: 0")
	})

	t.Run("SIGNED cert returns error", func(t *testing.T) {
		cert, _ := NewCertificateWithType(CERT_SIGNED, make([]byte, CERT_SIGNED_PAYLOAD_SHORT))
		_, err := GetSignatureTypeFromCertificate(*cert)
		require.Error(t, err)
	})

	t.Run("uninitialized cert returns error", func(t *testing.T) {
		var cert Certificate
		_, err := GetSignatureTypeFromCertificate(cert)
		require.Error(t, err)
	})

	t.Run("large signing type value", func(t *testing.T) {
		payload := make([]byte, 4)
		binary.BigEndian.PutUint16(payload[0:2], 65535)
		binary.BigEndian.PutUint16(payload[2:4], 0)
		cert, _ := NewCertificateWithType(CERT_KEY, payload)
		sigType, err := GetSignatureTypeFromCertificate(*cert)
		require.NoError(t, err)
		assert.Equal(t, 65535, sigType)
	})
}

func TestGetCryptoTypeFromCertificate(t *testing.T) {
	t.Run("valid KEY cert returns correct crypto type", func(t *testing.T) {
		payload := []byte{0x00, 0x07, 0x00, 0x04}
		cert, _ := NewCertificateWithType(CERT_KEY, payload)
		cryptoType, err := GetCryptoTypeFromCertificate(*cert)
		require.NoError(t, err)
		assert.Equal(t, 4, cryptoType)
	})

	t.Run("valid KEY cert with zero types", func(t *testing.T) {
		payload := []byte{0x00, 0x00, 0x00, 0x00}
		cert, _ := NewCertificateWithType(CERT_KEY, payload)
		cryptoType, err := GetCryptoTypeFromCertificate(*cert)
		require.NoError(t, err)
		assert.Equal(t, 0, cryptoType)
	})

	t.Run("NULL cert returns error", func(t *testing.T) {
		cert, _ := NewCertificateWithType(CERT_NULL, []byte{})
		_, err := GetCryptoTypeFromCertificate(*cert)
		require.Error(t, err)
	})

	t.Run("uninitialized cert returns error", func(t *testing.T) {
		var cert Certificate
		_, err := GetCryptoTypeFromCertificate(cert)
		require.Error(t, err)
	})

	t.Run("symmetric with GetSignatureTypeFromCertificate", func(t *testing.T) {
		payload := []byte{0x00, 0x07, 0x00, 0x04}
		cert, _ := NewCertificateWithType(CERT_KEY, payload)

		sigType, _ := GetSignatureTypeFromCertificate(*cert)
		assert.Equal(t, 7, sigType)

		cryptoType, _ := GetCryptoTypeFromCertificate(*cert)
		assert.Equal(t, 4, cryptoType)
	})
}

func TestGetSignatureTypeErrorSentinel(t *testing.T) {
	cert, _ := NewCertificateWithType(CERT_NULL, []byte{})

	sigType, err := GetSignatureTypeFromCertificate(*cert)
	require.Error(t, err)
	assert.Equal(t, CERT_EMPTY_PAYLOAD_SIZE, sigType)

	cryptoType, err := GetCryptoTypeFromCertificate(*cert)
	require.Error(t, err)
	assert.Equal(t, 0, cryptoType)
}

func TestSliceIndexCorrectness(t *testing.T) {
	t.Run("signature type extraction with 4-byte payload", func(t *testing.T) {
		payload := []byte{0x00, 0x07, 0x00, 0x04}
		cert, _ := NewCertificateWithType(CERT_KEY, payload)
		sigType, err := GetSignatureTypeFromCertificate(*cert)
		require.NoError(t, err)
		assert.Equal(t, 7, sigType)
	})

	t.Run("extraction with larger payload (extra padding)", func(t *testing.T) {
		payload := []byte{0x00, 0x07, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00}
		cert, _ := NewCertificateWithType(CERT_KEY, payload)
		sigType, _ := GetSignatureTypeFromCertificate(*cert)
		assert.Equal(t, 7, sigType)
		cryptoType, _ := GetCryptoTypeFromCertificate(*cert)
		assert.Equal(t, 4, cryptoType)
	})
}
