package certificate

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
)

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

func TestCertificateLengthErrWhenTooShort(t *testing.T) {
	assert := assert.New(t)

	bytes := []byte{0x03, 0x01}
	_, _, err := ReadCertificate(bytes)
	// If ReadCertificate returns an error, assert it and do not call methods on certificate
	if assert.NotNil(err, "ReadCertificate should return error for missing length data") {
		assert.Equal("error parsing certificate: certificate is too short", err.Error(), "correct error message should be returned")
	}
}

func TestCertificateLengthErrWhenDataTooShort(t *testing.T) {
	assert := assert.New(t)

	bytes := []byte{0x03, 0x00, 0x02, 0xff}
	_, _, err := ReadCertificate(bytes)
	// If ReadCertificate returns an error, assert it and do not call methods on certificate
	if assert.NotNil(err, "ReadCertificate should return error for data too short") {
		assert.Equal("certificate parsing warning: certificate data is shorter than specified by length", err.Error(), "correct error message should be returned")
	}
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

func TestCertificateDataWhenTooShort(t *testing.T) {
	assert := assert.New(t)

	bytes := []byte{0x03, 0x00, 0x02, 0xff}
	_, _, err := ReadCertificate(bytes)
	// If ReadCertificate returns an error, assert it and do not call methods on certificate
	if assert.NotNil(err, "ReadCertificate should return error for data too short") {
		assert.Equal("certificate parsing warning: certificate data is shorter than specified by length", err.Error(), "correct error message should be returned")
	}
}

func TestReadCertificateWithCorrectData(t *testing.T) {
	assert := assert.New(t)

	bytes := []byte{0x00, 0x00, 0x02, 0xff, 0xff}
	cert, remainder, err := ReadCertificate(bytes)

	assert.Equal(cert.length(), 5, "ReadCertificate() did not return correct amount of data for valid certificate")
	assert.Equal(len(remainder), 0, "ReadCertificate() did not return a zero length remainder on a valid certificate")
	assert.Nil(err, "ReadCertificate() should not return an error with valid data")
}

func TestReadCertificateWithDataTooShort(t *testing.T) {
	assert := assert.New(t)

	bytes := []byte{0x00, 0x00, 0x02, 0xff}
	cert, remainder, err := ReadCertificate(bytes)

	assert.Equal(cert.length(), 4, "ReadCertificate() did not return correct amount of data for certificate with missing data")
	assert.Equal(len(remainder), 0, "ReadCertificate() did not return a zero length remainder on certificate with missing data")
	if assert.NotNil(err) {
		assert.Equal("certificate parsing warning: certificate data is shorter than specified by length", err.Error(), "correct error message should be returned")
	}
}

func TestReadCertificateWithRemainder(t *testing.T) {
	assert := assert.New(t)

	bytes := []byte{0x00, 0x00, 0x02, 0xff, 0xff, 0x01}
	cert, remainder, err := ReadCertificate(bytes)

	assert.Equal(cert.length(), 5, "ReadCertificate() did not return correct amount of data for certificate with extra data")
	assert.Equal(len(remainder), 1, "ReadCertificate() returned incorrect length remainder on certificate with extra data")
	//	assert.Equal(1, int(remainder[0]), "ReadCertificate() did not return correct remainder value")
	assert.Nil(err)
}

func TestReadCertificateWithInvalidLength(t *testing.T) {
	assert := assert.New(t)

	bytes := []byte{0x00, 0x00}
	cert, remainder, err := ReadCertificate(bytes)

	assert.Equal(cert.length(), 2, "ReadCertificate() should populate the certificate with the provided data even when invalid")
	assert.Equal(len(remainder), 0, "ReadCertificate() returned non-zero length remainder on invalid certificate")
	if assert.NotNil(err) {
		assert.Equal("error parsing certificate: certificate is too short", err.Error(), "correct error message should be returned")
	}
}

func TestNewCertificateNullType(t *testing.T) {
	assert := assert.New(t)

	// Create a NULL certificate with no payload
	cert, err := NewCertificateWithType(CERT_NULL, []byte{})
	assert.Nil(err, "Expected no error when creating NULL certificate with empty payload")
	typ, typErr := cert.Type()
	assert.Nil(typErr, "Certificate type should not error for valid NULL type")
	assert.Equal(CERT_NULL, typ, "Certificate type should be CERT_NULL")
	length, lenErr := cert.Length()
	assert.Nil(lenErr, "Certificate length should not error for valid NULL certificate")
	assert.Equal(0, length, "Certificate length should be 0 for NULL certificate")
	data, dataErr := cert.Data()
	assert.Nil(dataErr, "Certificate data should not error for valid NULL certificate")
	assert.Equal(0, len(data), "Certificate data should be empty for NULL certificate")
}

func TestNewCertificateNullTypeWithPayload(t *testing.T) {
	assert := assert.New(t)

	// Attempt to create a NULL certificate with a payload (should fail)
	_, err := NewCertificateWithType(CERT_NULL, []byte{0x00})
	assert.NotNil(err, "Expected error when creating NULL certificate with payload")
	assert.Equal("NULL certificates must have empty payload", err.Error(), "Correct error message should be returned")
}

func TestNewCertificateKeyType(t *testing.T) {
	assert := assert.New(t)

	payload := []byte{0x00, 0x01, 0x02, 0x03, 0x04}
	cert, err := NewCertificateWithType(CERT_KEY, payload)
	assert.Nil(err, "Expected no error when creating KEY certificate with valid payload")
	typ, typErr := cert.Type()
	assert.Nil(typErr, "Certificate type should not error for valid KEY type")
	assert.Equal(CERT_KEY, typ, "Certificate type should be CERT_KEY")
	length, lenErr := cert.Length()
	assert.Nil(lenErr, "Certificate length should not error for valid KEY certificate")
	assert.Equal(len(payload), length, "Certificate length should match payload length")
	data, dataErr := cert.Data()
	assert.Nil(dataErr, "Certificate data should not error for valid KEY certificate")
	assert.Equal(payload, data, "Certificate data should match payload")
}

func TestNewCertificateInvalidType(t *testing.T) {
	assert := assert.New(t)

	invalidCertType := uint8(6) // Invalid type (valid types are 0-5)
	_, err := NewCertificateWithType(invalidCertType, []byte{})
	assert.NotNil(err, "Expected error when creating certificate with invalid type")
	assert.Equal("invalid certificate type: 6", err.Error(), "Correct error message should be returned")
}

/*
	func TestNewCertificatePayloadTooLong(t *testing.T) {
		assert := assert.New(t)

		// Create a payload that exceeds the maximum allowed length (65535 bytes)
		payload := make([]byte, 65536) // 65536 bytes
		_, err := NewCertificateWithType(CERT_KEY, payload)
		assert.NotNil(err, "Expected error when creating certificate with payload too long")
		assert.Equal("certificate payload too long: maximum length is 65535 bytes", err.Error(), "Correct error message should be returned")
	}
*/
func TestCertificateBytesSerialization(t *testing.T) {
	assert := assert.New(t)

	payload := []byte{0xAA, 0xBB, 0xCC}
	certType := CERT_SIGNED
	cert, err := NewCertificateWithType(uint8(certType), payload)
	assert.Nil(err, "Expected no error when creating SIGNED certificate")

	expectedBytes := []byte{
		byte(certType),           // Certificate type
		0x00, byte(len(payload)), // Certificate length (2 bytes)
		0xAA, 0xBB, 0xCC, // Payload
	}

	actualBytes := cert.Bytes()
	assert.Equal(expectedBytes, actualBytes, "Certificate bytes should match expected serialization")
}

func TestCertificateFieldsAfterCreation(t *testing.T) {
	assert := assert.New(t)

	payload := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	certType := CERT_MULTIPLE
	cert, err := NewCertificateWithType(uint8(certType), payload)
	assert.Nil(err, "Expected no error when creating MULTIPLE certificate")

	typ, typErr := cert.Type()
	assert.Nil(typErr, "Certificate type should not error for valid type")
	assert.Equal(certType, typ, "Certificate type should match")
	length, lenErr := cert.Length()
	assert.Nil(lenErr, "Certificate length should not error for valid certificate")
	assert.Equal(len(payload), length, "Certificate length should match payload length")
	data, dataErr := cert.Data()
	assert.Nil(dataErr, "Certificate data should not error for valid certificate")
	assert.Equal(payload, data, "Certificate data should match payload")
}

func TestCertificateWithZeroLengthPayload(t *testing.T) {
	assert := assert.New(t)

	certType := CERT_HASHCASH
	cert, err := NewCertificateWithType(uint8(certType), []byte{})
	assert.Nil(err, "Expected no error when creating certificate with zero-length payload")

	typ, typErr := cert.Type()
	assert.Nil(typErr, "Certificate type should not error for valid type")
	assert.Equal(certType, typ, "Certificate type should match")
	length, lenErr := cert.Length()
	assert.Nil(lenErr, "Certificate length should not error for valid certificate")
	assert.Equal(0, length, "Certificate length should be 0 for zero-length payload")
	data, dataErr := cert.Data()
	assert.Nil(dataErr, "Certificate data should not error for valid certificate")
	assert.Equal(0, len(data), "Certificate data should be empty")
}

func TestNewCertificateDeuxFunction(t *testing.T) {
	assert := assert.New(t)

	payload := []byte{0x11, 0x22}
	certType := CERT_HIDDEN
	cert, err := NewCertificateDeux(certType, payload)
	assert.Nil(err, "Expected no error when creating certificate with NewCertificateDeux")

	typ, typErr := cert.Type()
	assert.Nil(typErr, "Certificate type should not error for valid type")
	assert.Equal(certType, typ, "Certificate type should match")
	length, lenErr := cert.Length()
	assert.Nil(lenErr, "Certificate length should not error for valid certificate")
	assert.Equal(len(payload), length, "Certificate length should match payload length")
	data, dataErr := cert.Data()
	assert.Nil(dataErr, "Certificate data should not error for valid certificate")
	assert.Equal(payload, data, "Certificate data should match payload")
}

func TestNewCertificateWithInvalidPayloadLength(t *testing.T) {
	assert := assert.New(t)

	payload := make([]byte, 70000) // Exceeds 65535 bytes
	_, err := NewCertificateDeux(CERT_KEY, payload)
	assert.NotNil(err, "Expected error when creating certificate with payload exceeding maximum length")
	assert.Equal("payload too long: 70000 bytes", err.Error(), "Correct error message should be returned")
}

func TestCertificateExcessBytes(t *testing.T) {
	assert := assert.New(t)

	payload := []byte{0x01, 0x02}
	extraBytes := []byte{0x03, 0x04}
	certData := append(payload, extraBytes...)

	certBytes := append([]byte{byte(CERT_SIGNED)}, []byte{0x00, byte(len(payload))}...)
	certBytes = append(certBytes, certData...)

	cert, err := readCertificate(certBytes)
	assert.Nil(err, "Expected no error when reading certificate with excess bytes")

	excess := cert.ExcessBytes()
	assert.Equal(extraBytes, excess, "ExcessBytes should return the extra bytes in the payload")

	data, dataErr := cert.Data()
	assert.Nil(dataErr, "Certificate data should not error for valid certificate")
	assert.Equal(payload, data, "Data() should return the valid payload excluding excess bytes")
}

func TestCertificateSerializationDeserialization(t *testing.T) {
	assert := assert.New(t)

	payload := []byte{0xAA, 0xBB, 0xCC}
	certType := CERT_SIGNED

	originalCert, err := NewCertificateWithType(uint8(certType), payload)
	assert.Nil(err, "Expected no error when creating SIGNED certificate")

	serializedBytes := originalCert.Bytes()
	assert.NotNil(serializedBytes, "Serialized bytes should not be nil")

	deserializedCert, err := readCertificate(serializedBytes)
	assert.Nil(err, "Expected no error when deserializing certificate")

	origType, origTypeErr := originalCert.Type()
	deserType, deserTypeErr := deserializedCert.Type()
	assert.Nil(origTypeErr, "Original certificate type should not error")
	assert.Nil(deserTypeErr, "Deserialized certificate type should not error")
	assert.Equal(origType, deserType, "Certificate types should match")
	origLen, origLenErr := originalCert.Length()
	deserLen, deserLenErr := deserializedCert.Length()
	assert.Nil(origLenErr, "Original certificate length should not error")
	assert.Nil(deserLenErr, "Deserialized certificate length should not error")
	assert.Equal(origLen, deserLen, "Certificate lengths should match")
	origData, origDataErr := originalCert.Data()
	deserData, deserDataErr := deserializedCert.Data()
	assert.Nil(origDataErr, "Original certificate data should not error")
	assert.Nil(deserDataErr, "Deserialized certificate data should not error")
	assert.Equal(origData, deserData, "Certificate payloads should match")
}

func TestCertificateSerializationDeserializationWithExcessBytes(t *testing.T) {
	assert := assert.New(t)

	payload := []byte{0x01, 0x02}
	certType := CERT_MULTIPLE

	originalCert, err := NewCertificateWithType(uint8(certType), payload)
	assert.Nil(err, "Expected no error when creating MULTIPLE certificate")

	serializedBytes := originalCert.Bytes()

	excessBytes := []byte{0x03, 0x04}
	serializedBytesWithExcess := append(serializedBytes, excessBytes...)

	deserializedCert, err := readCertificate(serializedBytesWithExcess)
	assert.Nil(err, "Expected no error when deserializing certificate with excess bytes")

	origType, origTypeErr := originalCert.Type()
	deserType, deserTypeErr := deserializedCert.Type()
	assert.Nil(origTypeErr, "Original certificate type should not error")
	assert.Nil(deserTypeErr, "Deserialized certificate type should not error")
	assert.Equal(origType, deserType, "Certificate types should match")
	origLen, origLenErr := originalCert.Length()
	deserLen, deserLenErr := deserializedCert.Length()
	assert.Nil(origLenErr, "Original certificate length should not error")
	assert.Nil(deserLenErr, "Deserialized certificate length should not error")
	assert.Equal(origLen, deserLen, "Certificate lengths should match")
	origData, origDataErr := originalCert.Data()
	deserData, deserDataErr := deserializedCert.Data()
	assert.Nil(origDataErr, "Original certificate data should not error")
	assert.Nil(deserDataErr, "Deserialized certificate data should not error")
	assert.Equal(origData, deserData, "Certificate payloads should match")

	excess := deserializedCert.ExcessBytes()
	assert.Equal(excessBytes, excess, "ExcessBytes should return the extra bytes appended to the serialized data")
}

func TestCertificateSerializationDeserializationEmptyPayload(t *testing.T) {
	assert := assert.New(t)

	payload := []byte{}
	certType := CERT_NULL

	originalCert, err := NewCertificateWithType(uint8(certType), payload)
	assert.Nil(err, "Expected no error when creating NULL certificate")

	serializedBytes := originalCert.Bytes()

	deserializedCert, err := readCertificate(serializedBytes)
	assert.Nil(err, "Expected no error when deserializing NULL certificate")

	origType, origTypeErr := originalCert.Type()
	deserType, deserTypeErr := deserializedCert.Type()
	assert.Nil(origTypeErr, "Original certificate type should not error")
	assert.Nil(deserTypeErr, "Deserialized certificate type should not error")
	assert.Equal(origType, deserType, "Certificate types should match")
	origLen, origLenErr := originalCert.Length()
	deserLen, deserLenErr := deserializedCert.Length()
	assert.Nil(origLenErr, "Original certificate length should not error")
	assert.Nil(deserLenErr, "Deserialized certificate length should not error")
	assert.Equal(origLen, deserLen, "Certificate lengths should match")
	origData, origDataErr := originalCert.Data()
	deserData, deserDataErr := deserializedCert.Data()
	assert.Nil(origDataErr, "Original certificate data should not error")
	assert.Nil(deserDataErr, "Deserialized certificate data should not error")
	assert.Equal(origData, deserData, "Certificate payloads should match")
}

func TestCertificateSerializationDeserializationMaxPayload(t *testing.T) {
	assert := assert.New(t)

	payload := make([]byte, 65535)
	for i := range payload {
		payload[i] = byte(i % 256)
	}
	certType := CERT_KEY

	originalCert, err := NewCertificateWithType(uint8(certType), payload)
	assert.Nil(err, "Expected no error when creating KEY certificate with maximum payload")

	serializedBytes := originalCert.Bytes()
	assert.Equal(1+2+65535, len(serializedBytes), "Serialized bytes length should be correct for maximum payload")

	deserializedCert, err := readCertificate(serializedBytes)
	assert.Nil(err, "Expected no error when deserializing certificate with maximum payload")

	origType, origTypeErr := originalCert.Type()
	deserType, deserTypeErr := deserializedCert.Type()
	assert.Nil(origTypeErr, "Original certificate type should not error")
	assert.Nil(deserTypeErr, "Deserialized certificate type should not error")
	assert.Equal(origType, deserType, "Certificate types should match")
	origLen, origLenErr := originalCert.Length()
	deserLen, deserLenErr := deserializedCert.Length()
	assert.Nil(origLenErr, "Original certificate length should not error")
	assert.Nil(deserLenErr, "Deserialized certificate length should not error")
	assert.Equal(origLen, deserLen, "Certificate lengths should match")
	origData, origDataErr := originalCert.Data()
	deserData, deserDataErr := deserializedCert.Data()
	assert.Nil(origDataErr, "Original certificate data should not error")
	assert.Nil(deserDataErr, "Deserialized certificate data should not error")
	assert.True(bytes.Equal(origData, deserData), "Certificate payloads should match")
}

func TestCertificateHandlesOneByte(t *testing.T) {
	assert := assert.New(t)

	// Test the audit case: 1-byte input should not panic and handle edge case properly
	bytes := []byte{0x03}
	certificate, _, err := ReadCertificate(bytes)

	// Should return error and not panic
	assert.NotNil(err, "ReadCertificate should return error for 1-byte input")
	assert.Equal("error parsing certificate: certificate is too short", err.Error())

	// Certificate kind should be safely extracted from the available data
	kind_int := certificate.kind.Int()
	assert.Equal(3, kind_int, "Certificate kind should be extracted from available byte")

	// Length should be zero for short certificate
	length_int := certificate.len.Int()
	assert.Equal(0, length_int, "Certificate length should be zero for short certificate")
}

func TestCertificateHandlesZeroBytes(t *testing.T) {
	assert := assert.New(t)

	// Test zero-byte input edge case
	bytes := []byte{}
	_, _, err := ReadCertificate(bytes)

	// Should return error for empty input
	assert.NotNil(err, "ReadCertificate should return error for empty input")
	assert.Equal("error parsing certificate: certificate is empty", err.Error())
}
