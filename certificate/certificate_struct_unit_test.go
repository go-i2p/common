package certificate

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Unit tests for certificate_struct.go — Certificate struct methods, constructors

func TestCertificateTypeIsFirstByte(t *testing.T) {
	assert := assert.New(t)

	// Use CERT_KEY (5) with a 4-byte payload — a valid KEY certificate.
	bytes := []byte{0x05, 0x00, 0x04, 0x00, 0x07, 0x00, 0x04}
	certificate, _, _ := ReadCertificate(bytes)
	cert_type, typeErr := certificate.Type()
	assert.Nil(typeErr, "certificate.Type() should not error for valid type")
	assert.Equal(cert_type, 5, "certificate.Type() should be the first byte in a certificate")
}

func TestCertificateLengthCorrect(t *testing.T) {
	assert := assert.New(t)

	// Use CERT_KEY (5) with a 4-byte payload — a valid KEY certificate.
	bytes := []byte{0x05, 0x00, 0x04, 0x00, 0x07, 0x00, 0x04}
	certificate, _, _ := ReadCertificate(bytes)
	cert_len, lenErr := certificate.Length()
	assert.Nil(lenErr, "certificate.Length() should not error for valid length")
	assert.Equal(cert_len, 4, "certificate.Length() should return integer from second two bytes")
}

func TestCertificateDataWhenCorrectSize(t *testing.T) {
	assert := assert.New(t)

	// Use CERT_KEY (5) with a 4-byte payload — a valid KEY certificate.
	bytes := []byte{0x05, 0x00, 0x04, 0x00, 0x07, 0x00, 0x04}
	certificate, _, _ := ReadCertificate(bytes)
	cert_data, dataErr := certificate.Data()
	assert.Nil(dataErr, "certificate.Data() returned error with valid data")
	cert_len := len(cert_data)
	assert.Equal(cert_len, 4, "certificate.Data() did not return indicated length when data was valid")
	assert.Equal(0x00, int(cert_data[0]), "certificate.Data() returned incorrect data")
}

func TestCertificateDataWhenTooLong(t *testing.T) {
	assert := assert.New(t)

	// Use CERT_KEY (5) with a 4-byte payload followed by extra stream bytes.
	// Input has extra bytes beyond the declared payload; ReadCertificate returns
	// those as remainder, not stored in the certificate payload.
	bytes := []byte{0x05, 0x00, 0x04, 0x00, 0x07, 0x00, 0x04, 0xaa, 0xaa}
	certificate, _, _ := ReadCertificate(bytes)
	cert_data, dataErr := certificate.Data()
	assert.Nil(dataErr, "certificate.Data() should not error for valid length")
	cert_len, lenErr := certificate.Length()
	assert.Nil(lenErr, "certificate.Length() should not error for valid length")
	assert.Equal(cert_len, 4, "certificate.Length() did not return indicated length when data was too long")
	if cert_data[0] != 0x00 || cert_data[1] != 0x07 {
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
	// HASHCASH now requires non-empty ASCII payload per spec.
	// Zero-length HASHCASH should be rejected.
	_, err := NewCertificateWithType(uint8(CERT_HASHCASH), []byte{})
	assert.NotNil(t, err, "HASHCASH with empty payload should be rejected per spec")

	// NULL cert has a zero-length payload and should work.
	cert, err := NewCertificateWithType(uint8(CERT_NULL), []byte{})
	assert.Nil(t, err)

	typ, _ := cert.Type()
	assert.Equal(t, CERT_NULL, typ)
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
		cert, _ := NewCertificateWithType(CERT_KEY, []byte{0x01, 0x02, 0x03, 0x04})
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

	t.Run("identical after ReadCertificate because payload is trimmed to declared length", func(t *testing.T) {
		// After the payload-capture fix, ReadCertificate stores only declared-length bytes.
		// Bytes() and RawBytes() therefore produce the same output for any parsed cert.
		wireData := []byte{CERT_KEY, 0x00, 0x04, 0x00, 0x07, 0x00, 0x04, 0xFF, 0xFF}
		cert, remainder, err := ReadCertificate(wireData)
		require.NoError(t, err)
		assert.Equal(t, []byte{0xFF, 0xFF}, remainder)
		assert.Equal(t, cert.Bytes(), cert.RawBytes(),
			"Bytes() and RawBytes() must be identical when payload is trimmed to declared length")
		assert.Equal(t, CERT_MIN_SIZE+4, len(cert.Bytes()))
	})

	t.Run("both nil on invalid certificate", func(t *testing.T) {
		var cert Certificate
		assert.Nil(t, cert.Bytes())
		assert.Nil(t, cert.RawBytes())
	})
}

func TestCertificateExcessBytes(t *testing.T) {
	// After the payload-capture fix, ReadCertificate stores only declared-length bytes.
	// ExcessBytes() is therefore always nil for certificates parsed from the wire.
	// Post-certificate stream bytes are returned as the remainder, not via ExcessBytes.
	t.Run("parsed cert ExcessBytes is nil", func(t *testing.T) {
		payload := make([]byte, CERT_SIGNED_PAYLOAD_SHORT)
		cert, err := NewCertificateWithType(CERT_SIGNED, payload)
		require.NoError(t, err)
		assert.Nil(t, cert.ExcessBytes())
	})

	t.Run("KEY cert parsed from wire ExcessBytes is nil", func(t *testing.T) {
		certBytes := []byte{byte(CERT_KEY), 0x00, 0x04, 0x00, 0x07, 0x00, 0x04}
		cert, remainder, err := ReadCertificate(certBytes)
		require.NoError(t, err)
		assert.Nil(t, cert.ExcessBytes())
		assert.Nil(t, remainder)
	})

	t.Run("post-certificate stream bytes returned as remainder, not ExcessBytes", func(t *testing.T) {
		// MULTIPLE cert: declared 3 bytes, followed by 2 extra stream bytes.
		certBytes := []byte{byte(CERT_MULTIPLE), 0x00, 0x03, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE}
		cert, remainder, err := ReadCertificate(certBytes)
		require.NoError(t, err)
		data, _ := cert.Data()
		assert.Equal(t, []byte{0xAA, 0xBB, 0xCC}, data)
		assert.Equal(t, []byte{0xDD, 0xEE}, remainder)
		assert.Nil(t, cert.ExcessBytes(), "stream bytes after cert must not appear in ExcessBytes")
	})
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
	assert.Equal(t, -1, sigType, "error sentinel should be -1 to avoid collision with DSA_SHA1 type 0")

	cryptoType, err := GetCryptoTypeFromCertificate(*cert)
	require.Error(t, err)
	assert.Equal(t, -1, cryptoType, "error sentinel must be -1 to not collide with ElGamal crypto type 0")
}

func TestNewCertificateWithType_KeyCertMinPayload(t *testing.T) {
	t.Run("CERT_KEY with 0-byte payload rejected", func(t *testing.T) {
		_, err := NewCertificateWithType(CERT_KEY, []byte{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "KEY certificates require at least")
	})

	t.Run("CERT_KEY with 1-byte payload rejected", func(t *testing.T) {
		_, err := NewCertificateWithType(CERT_KEY, []byte{0x01})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "KEY certificates require at least")
	})

	t.Run("CERT_KEY with 2-byte payload rejected", func(t *testing.T) {
		_, err := NewCertificateWithType(CERT_KEY, []byte{0x01, 0x02})
		require.Error(t, err)
	})

	t.Run("CERT_KEY with 3-byte payload rejected", func(t *testing.T) {
		_, err := NewCertificateWithType(CERT_KEY, []byte{0x01, 0x02, 0x03})
		require.Error(t, err)
	})

	t.Run("CERT_KEY with exactly 4-byte payload accepted", func(t *testing.T) {
		cert, err := NewCertificateWithType(CERT_KEY, []byte{0x00, 0x07, 0x00, 0x04})
		require.NoError(t, err)
		require.NotNil(t, cert)
	})

	t.Run("CERT_KEY with 5-byte payload accepted", func(t *testing.T) {
		cert, err := NewCertificateWithType(CERT_KEY, []byte{0x00, 0x07, 0x00, 0x04, 0x00})
		require.NoError(t, err)
		require.NotNil(t, cert)
	})

	t.Run("usable for GetSignatureType after construction", func(t *testing.T) {
		cert, err := NewCertificateWithType(CERT_KEY, []byte{0x00, 0x07, 0x00, 0x04})
		require.NoError(t, err)
		sigType, err := GetSignatureTypeFromCertificate(*cert)
		require.NoError(t, err)
		assert.Equal(t, 7, sigType)
	})
}

func TestExcessBytes_ExactMatch_ReturnsNil(t *testing.T) {
	t.Run("payload exactly matches declared length returns nil", func(t *testing.T) {
		payload := []byte{0x00, 0x07, 0x00, 0x04}
		cert, _ := NewCertificateWithType(CERT_KEY, payload)
		excess := cert.ExcessBytes()
		assert.Nil(t, excess,
			"ExcessBytes should return nil (not empty slice) when payload matches declared length")
	})

	t.Run("NULL cert with no payload returns nil", func(t *testing.T) {
		cert := NewCertificate()
		excess := cert.ExcessBytes()
		assert.Nil(t, excess)
	})

	t.Run("payload matches declared length after ReadCertificate", func(t *testing.T) {
		// KEY cert with exact 4-byte payload — ExcessBytes() must be nil.
		wireData := []byte{CERT_KEY, 0x00, 0x04, 0x00, 0x07, 0x00, 0x04}
		cert, _, err := ReadCertificate(wireData)
		require.NoError(t, err)
		excess := cert.ExcessBytes()
		assert.Nil(t, excess, "ExcessBytes() must be nil when payload equals declared length")
	})
}

func TestCertificate_String(t *testing.T) {
	t.Run("NULL certificate", func(t *testing.T) {
		cert := NewCertificate()
		s := cert.String()
		assert.Contains(t, s, "NULL")
		assert.Contains(t, s, "length: 0")
	})

	t.Run("KEY certificate", func(t *testing.T) {
		cert, _ := NewCertificateWithType(CERT_KEY, []byte{0x00, 0x07, 0x00, 0x04})
		s := cert.String()
		assert.Contains(t, s, "KEY")
		assert.Contains(t, s, "length: 4")
	})

	t.Run("nil certificate", func(t *testing.T) {
		var cert *Certificate
		s := cert.String()
		assert.Equal(t, "Certificate{invalid}", s)
	})

	t.Run("zero value certificate", func(t *testing.T) {
		var cert Certificate
		s := cert.String()
		assert.Equal(t, "Certificate{invalid}", s)
	})

	t.Run("all known types have names", func(t *testing.T) {
		types := map[uint8]string{
			CERT_NULL:     "NULL",
			CERT_HASHCASH: "HASHCASH",
			CERT_HIDDEN:   "HIDDEN",
			CERT_SIGNED:   "SIGNED",
			CERT_MULTIPLE: "MULTIPLE",
			CERT_KEY:      "KEY",
		}
		for certType, name := range types {
			t.Run(name, func(t *testing.T) {
				assert.Contains(t, certTypeName(int(certType)), name)
			})
		}
	})

	t.Run("unknown type shows UNKNOWN", func(t *testing.T) {
		assert.Contains(t, certTypeName(99), "UNKNOWN")
	})
}

func TestCertificate_GoString(t *testing.T) {
	t.Run("KEY certificate includes package prefix", func(t *testing.T) {
		cert, _ := NewCertificateWithType(CERT_KEY, []byte{0x00, 0x07, 0x00, 0x04})
		s := cert.GoString()
		assert.Contains(t, s, "certificate.Certificate")
		assert.Contains(t, s, "KEY")
		assert.Contains(t, s, "4 bytes")
	})

	t.Run("nil certificate", func(t *testing.T) {
		var cert *Certificate
		s := cert.GoString()
		assert.Contains(t, s, "invalid")
	})
}

func TestCertificate_Stringer_Interface(t *testing.T) {
	cert := NewCertificate()
	s := fmt.Sprintf("%s", cert)
	assert.Contains(t, s, "NULL")
}

func TestCertificate_GoStringer_Interface(t *testing.T) {
	cert := NewCertificate()
	s := fmt.Sprintf("%#v", cert)
	assert.Contains(t, s, "certificate.Certificate")
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

// TestRoundTripAllCertificateTypes verifies that every defined certificate type survives
// a Bytes() → ReadCertificate() round-trip with identical field values.
// Exercises HASHCASH and MULTIPLE which were not previously covered by round-trip tests.
func TestRoundTripAllCertificateTypes(t *testing.T) {
	tests := []struct {
		name    string
		build   func() (*Certificate, error)
		wantLen int
	}{
		{
			name:    "NULL",
			build:   func() (*Certificate, error) { return NewCertificateWithType(CERT_NULL, []byte{}) },
			wantLen: 0,
		},
		{
			name: "HASHCASH",
			build: func() (*Certificate, error) {
				// Spec: ASCII colon-separated hashcash string.
				return NewCertificateWithType(CERT_HASHCASH, []byte("1:20:000000:test@i2p::000000:000000"))
			},
			wantLen: len("1:20:000000:test@i2p::000000:000000"),
		},
		{
			name:    "HIDDEN",
			build:   func() (*Certificate, error) { return NewCertificateWithType(CERT_HIDDEN, []byte{}) },
			wantLen: 0,
		},
		{
			name: "SIGNED",
			build: func() (*Certificate, error) {
				return NewCertificateWithType(CERT_SIGNED, make([]byte, CERT_SIGNED_PAYLOAD_SHORT))
			},
			wantLen: CERT_SIGNED_PAYLOAD_SHORT,
		},
		{
			name: "MULTIPLE",
			build: func() (*Certificate, error) {
				return NewCertificateWithType(CERT_MULTIPLE, []byte{0xDE, 0xAD, 0xBE, 0xEF})
			},
			wantLen: 4,
		},
		{
			name: "KEY",
			build: func() (*Certificate, error) {
				return NewCertificateWithType(CERT_KEY, []byte{0x00, 0x07, 0x00, 0x04})
			},
			wantLen: 4,
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			original, err := tc.build()
			require.NoError(t, err)
			require.NotNil(t, original)

			serialized := original.Bytes()
			require.NotNil(t, serialized)

			parsed, remainder, err := ReadCertificate(serialized)
			require.NoError(t, err)
			require.NotNil(t, parsed)
			assert.Empty(t, remainder, "no remainder expected after exact serialization")

			origType, _ := original.Type()
			parsedType, _ := parsed.Type()
			assert.Equal(t, origType, parsedType, "type must survive round-trip")

			origLen, _ := original.Length()
			parsedLen, _ := parsed.Length()
			assert.Equal(t, origLen, parsedLen, "length must survive round-trip")
			assert.Equal(t, tc.wantLen, parsedLen)

			origData, _ := original.Data()
			parsedData, _ := parsed.Data()
			assert.Equal(t, origData, parsedData, "payload must survive round-trip")
		})
	}
}

// TestBuildCertificateGuardUsesLenPayload verifies the fix for AUDIT BUG:
// buildCertificate now uses `len(payload) > 0` instead of `len(payload) > CERT_EMPTY_PAYLOAD_SIZE`,
// ensuring the copy always happens when there are bytes to copy.
func TestBuildCertificateGuardUsesLenPayload(t *testing.T) {
	// CERT_KEY with a 4-byte payload: verify the payload is actually copied into the certificate.
	payload := []byte{0x00, 0x07, 0x00, 0x04}
	cert, err := NewCertificateWithType(CERT_KEY, payload)
	require.NoError(t, err)

	data, err := cert.Data()
	require.NoError(t, err)
	assert.Equal(t, payload, data, "payload should be faithfully copied into certificate")

	// Mutate original payload — should not affect the certificate (defensive copy in buildCertificate).
	payload[0] = 0xFF
	data2, _ := cert.Data()
	assert.NotEqual(t, payload, data2, "mutating original payload should not affect certificate")
}

// TestDataReturnsDefensiveCopy verifies the fix for AUDIT GAP:
// Data() now returns a defensive copy, not a sub-slice of internal storage.
func TestDataReturnsDefensiveCopy(t *testing.T) {
	payload := []byte{0x00, 0x07, 0x00, 0x04}
	cert, err := NewCertificateWithType(CERT_KEY, payload)
	require.NoError(t, err)

	data1, err := cert.Data()
	require.NoError(t, err)

	// Mutate the returned data
	data1[0] = 0xFF

	// Get Data() again — should not reflect the mutation
	data2, err := cert.Data()
	require.NoError(t, err)
	assert.Equal(t, byte(0x00), data2[0], "mutating Data() return value must not corrupt internal state")

	// Verify data2 is a fresh copy (not the same slice header)
	data2[1] = 0xFF
	data3, _ := cert.Data()
	assert.Equal(t, byte(0x07), data3[1], "each Data() call must return an independent copy")
}

// TestHashcashValidation verifies the fix for AUDIT SPEC:
// HASHCASH certificates must have non-empty ASCII printable payloads per spec.
func TestHashcashValidation(t *testing.T) {
	t.Run("empty payload rejected", func(t *testing.T) {
		_, err := NewCertificateWithType(CERT_HASHCASH, []byte{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "non-empty")
	})

	t.Run("non-ASCII payload rejected", func(t *testing.T) {
		_, err := NewCertificateWithType(CERT_HASHCASH, []byte{0x01, 0x02, 0x03})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "non-printable ASCII")
	})

	t.Run("valid ASCII hashcash accepted", func(t *testing.T) {
		hashcash := []byte("1:20:060408:adam@cypherspace.org::1QTjaYd7niiQA/sc:ePa")
		cert, err := NewCertificateWithType(CERT_HASHCASH, hashcash)
		require.NoError(t, err)
		data, _ := cert.Data()
		assert.Equal(t, hashcash, data)
	})

	t.Run("ReadCertificate rejects non-ASCII HASHCASH from wire", func(t *testing.T) {
		// Construct wire bytes: type=1 (HASHCASH), length=3, payload=[0x01, 0x02, 0x03]
		wireBytes := []byte{CERT_HASHCASH, 0x00, 0x03, 0x01, 0x02, 0x03}
		cert, _, err := ReadCertificate(wireBytes)
		require.Error(t, err)
		assert.Nil(t, cert)
	})

	t.Run("ReadCertificate rejects empty HASHCASH from wire", func(t *testing.T) {
		wireBytes := []byte{CERT_HASHCASH, 0x00, 0x00}
		cert, _, err := ReadCertificate(wireBytes)
		require.Error(t, err)
		assert.Nil(t, cert)
	})
}

// TestMultipleValidation verifies the fix for AUDIT SPEC:
// MULTIPLE certificates must have at least CERT_MIN_SIZE (3) bytes of payload.
func TestMultipleValidation(t *testing.T) {
	t.Run("empty payload rejected for construction", func(t *testing.T) {
		_, err := NewCertificateWithType(CERT_MULTIPLE, []byte{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "sub-certificate")
	})

	t.Run("1-byte payload rejected for construction", func(t *testing.T) {
		_, err := NewCertificateWithType(CERT_MULTIPLE, []byte{0x01})
		require.Error(t, err)
	})

	t.Run("2-byte payload rejected for construction", func(t *testing.T) {
		_, err := NewCertificateWithType(CERT_MULTIPLE, []byte{0x01, 0x02})
		require.Error(t, err)
	})

	t.Run("3-byte payload accepted (minimal sub-cert)", func(t *testing.T) {
		// A NULL sub-certificate is exactly 3 bytes: type=0, length=0x0000
		cert, err := NewCertificateWithType(CERT_MULTIPLE, []byte{0x00, 0x00, 0x00})
		require.NoError(t, err)
		typ, _ := cert.Type()
		assert.Equal(t, CERT_MULTIPLE, typ)
	})

	t.Run("ReadCertificate rejects 2-byte MULTIPLE from wire", func(t *testing.T) {
		wireBytes := []byte{CERT_MULTIPLE, 0x00, 0x02, 0xAA, 0xBB}
		cert, _, err := ReadCertificate(wireBytes)
		require.Error(t, err)
		assert.Nil(t, cert)
	})

	t.Run("ReadCertificate accepts 3-byte MULTIPLE from wire", func(t *testing.T) {
		wireBytes := []byte{CERT_MULTIPLE, 0x00, 0x03, 0x00, 0x00, 0x00}
		cert, _, err := ReadCertificate(wireBytes)
		require.NoError(t, err)
		require.NotNil(t, cert)
		typ, _ := cert.Type()
		assert.Equal(t, CERT_MULTIPLE, typ)
	})
}
