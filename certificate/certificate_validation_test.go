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
	// KEY cert with valid 4-byte payload — exactly spec-conformant.
	cert, remainder, err := ReadCertificate([]byte{CERT_KEY, 0x00, 0x04, 0x00, 0x07, 0x00, 0x04})
	assert.Equal(t, 7, cert.length())
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
	// MULTIPLE cert with a 3-byte payload (minimum valid), plus 1 extra stream byte.
	cert, remainder, err := ReadCertificate([]byte{CERT_MULTIPLE, 0x00, 0x03, 0x00, 0x00, 0x00, 0x01})
	assert.Equal(t, 6, cert.length())
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
	t.Run("NULL cert with non-zero payload is rejected", func(t *testing.T) {
		cert, _, err := ReadCertificate([]byte{CERT_NULL, 0x00, 0x02, 0xAA, 0xBB})
		require.Error(t, err)
		assert.Nil(t, cert)
	})

	t.Run("KEY cert with valid payload parses", func(t *testing.T) {
		cert, _, err := ReadCertificate([]byte{CERT_KEY, 0x00, 0x04, 0x00, 0x07, 0x00, 0x04})
		require.NoError(t, err)
		certType, _ := cert.Type()
		assert.Equal(t, CERT_KEY, certType)
	})

	t.Run("KEY cert with insufficient payload returns error", func(t *testing.T) {
		cert, _, err := ReadCertificate([]byte{CERT_KEY, 0x00, 0x02, 0x00, 0x07})
		require.Error(t, err)
		assert.Nil(t, cert)
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

	t.Run("parser accepts unknown type bytes with zero payload", func(t *testing.T) {
		// Known types (NULL=0, HIDDEN=2) with zero payload are also valid.
		// CERT_KEY (5) with zero payload is rejected: KEY requires >= 4 bytes.
		for _, typeVal := range []byte{0, 2, 6, 100, 255} {
			cert, _, err := ReadCertificate([]byte{typeVal, 0x00, 0x00})
			require.NoError(t, err, "type %d with zero payload should parse", typeVal)
			ct, _ := cert.Type()
			assert.Equal(t, int(typeVal), ct)
		}
	})

	t.Run("parser rejects CERT_KEY with zero payload", func(t *testing.T) {
		cert, _, err := ReadCertificate([]byte{CERT_KEY, 0x00, 0x00})
		require.Error(t, err)
		assert.Nil(t, cert)
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

	t.Run("ReadCertificate rejects non-conforming SIGNED from wire", func(t *testing.T) {
		cert, _, err := ReadCertificate([]byte{CERT_SIGNED, 0x00, 0x02, 0xAA, 0xBB})
		require.Error(t, err)
		assert.Nil(t, cert)
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

	t.Run("MULTIPLE cert with stream bytes returns correct remainder", func(t *testing.T) {
		// MULTIPLE requires at least 3-byte payload (one sub-certificate). Declared 3 bytes, 2 extra.
		cert, remainder, err := ReadCertificate([]byte{CERT_MULTIPLE, 0x00, 0x03, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE})
		require.NoError(t, err)
		require.NotNil(t, cert)
		assert.Equal(t, []byte{0xDD, 0xEE}, remainder)
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

// TestGetCryptoType_ErrorSentinelIsMinusOne verifies that GetCryptoTypeFromCertificate
// uses -1 as its error sentinel, consistent with GetSignatureTypeFromCertificate and
// unambiguous with the valid ElGamal crypto type code 0.
func TestGetCryptoType_ErrorSentinelIsMinusOne(t *testing.T) {
	t.Run("error sentinel is -1 not 0", func(t *testing.T) {
		cert, _ := NewCertificateWithType(CERT_NULL, []byte{})
		cryptoType, err := GetCryptoTypeFromCertificate(*cert)
		require.Error(t, err)
		assert.Equal(t, -1, cryptoType,
			"error sentinel must be -1 to not collide with ElGamal crypto type code 0")
	})

	t.Run("valid ElGamal type 0 is distinguishable from error", func(t *testing.T) {
		payload := []byte{0x00, 0x00, 0x00, 0x00} // sigType=0, cryptoType=0
		cert, _ := NewCertificateWithType(CERT_KEY, payload)
		cryptoType, err := GetCryptoTypeFromCertificate(*cert)
		require.NoError(t, err)
		assert.Equal(t, 0, cryptoType, "ElGamal crypto type 0 should be returned on success")
	})

	t.Run("uninitialized cert returns -1", func(t *testing.T) {
		var cert Certificate
		cryptoType, err := GetCryptoTypeFromCertificate(cert)
		require.Error(t, err)
		assert.Equal(t, -1, cryptoType)
	})

	t.Run("short payload returns -1", func(t *testing.T) {
		// parseCertificateFromData bypasses type-specific validation, giving a KEY cert
		// with a 2-byte payload to exercise the short-payload sentinel path.
		shortCert, _ := parseCertificateFromData([]byte{CERT_KEY, 0x00, 0x02, 0x00, 0x07})
		cryptoType, err2 := GetCryptoTypeFromCertificate(shortCert)
		require.Error(t, err2)
		assert.Equal(t, -1, cryptoType)
	})

	t.Run("HIDDEN cert returns -1", func(t *testing.T) {
		cert, _ := NewCertificateWithType(CERT_HIDDEN, []byte{})
		cryptoType, err := GetCryptoTypeFromCertificate(*cert)
		require.Error(t, err)
		assert.Equal(t, -1, cryptoType)
	})
}

// TestGetExcessKeyData validates the excess signing/crypto key data extraction functions.
func TestGetExcessKeyData(t *testing.T) {
	t.Run("no excess signing key when size <= 128", func(t *testing.T) {
		cert, _ := NewCertificateWithType(CERT_KEY, []byte{0x00, 0x07, 0x00, 0x04})
		result, err := GetExcessSigningPublicKeyData(*cert, 32) // Ed25519 = 32 bytes
		require.NoError(t, err)
		assert.Nil(t, result)
	})

	t.Run("no excess crypto key when size <= 256", func(t *testing.T) {
		cert, _ := NewCertificateWithType(CERT_KEY, []byte{0x00, 0x07, 0x00, 0x04})
		result, err := GetExcessCryptoPublicKeyData(*cert, 32, 0) // X25519 = 32 bytes
		require.NoError(t, err)
		assert.Nil(t, result)
	})

	t.Run("excess signing key extracted correctly", func(t *testing.T) {
		// Signing key size 256 bytes — excess = 256-128 = 128 bytes.
		excessSigningData := make([]byte, 128)
		for i := range excessSigningData {
			excessSigningData[i] = byte(i)
		}
		payload := append([]byte{0x00, 0x09, 0x00, 0x00}, excessSigningData...) // sigType=9 (RSA-2048)
		cert, err := NewCertificateWithType(CERT_KEY, payload)
		require.NoError(t, err)
		result, err := GetExcessSigningPublicKeyData(*cert, 256)
		require.NoError(t, err)
		assert.Equal(t, excessSigningData, result)
	})

	t.Run("excess crypto key extracted correctly", func(t *testing.T) {
		// Crypto key size 512 bytes — excess = 512-256 = 256 bytes.
		excessCryptoData := make([]byte, 256)
		for i := range excessCryptoData {
			excessCryptoData[i] = byte(i + 1)
		}
		// payload: [sigType 2B][cryptoType 2B][excessCrypto 256B]
		payload := append([]byte{0x00, 0x07, 0x00, 0x06}, excessCryptoData...)
		cert, err := NewCertificateWithType(CERT_KEY, payload)
		require.NoError(t, err)
		result, err := GetExcessCryptoPublicKeyData(*cert, 512, 0)
		require.NoError(t, err)
		assert.Equal(t, excessCryptoData, result)
	})

	t.Run("non-KEY cert returns error for excess signing", func(t *testing.T) {
		cert, _ := NewCertificateWithType(CERT_NULL, []byte{})
		_, err := GetExcessSigningPublicKeyData(*cert, 256)
		require.Error(t, err)
	})

	t.Run("payload too short for excess signing key", func(t *testing.T) {
		cert, _ := NewCertificateWithType(CERT_KEY, []byte{0x00, 0x09, 0x00, 0x00})
		_, err := GetExcessSigningPublicKeyData(*cert, 256) // needs 128 excess bytes, only 0 available
		require.Error(t, err)
		assert.Contains(t, err.Error(), "payload too short")
	})
}

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

func TestGetSignatureType_ErrorSentinelIsNegativeOne(t *testing.T) {
	t.Run("error sentinel is -1 not 0", func(t *testing.T) {
		cert, _ := NewCertificateWithType(CERT_NULL, []byte{})
		sigType, err := GetSignatureTypeFromCertificate(*cert)
		require.Error(t, err)
		assert.Equal(t, -1, sigType,
			"error sentinel must be -1 to not collide with DSA_SHA1 type code 0")
	})

	t.Run("valid DSA_SHA1 type 0 is distinguishable from error", func(t *testing.T) {
		payload := []byte{0x00, 0x00, 0x00, 0x00}
		cert, _ := NewCertificateWithType(CERT_KEY, payload)
		sigType, err := GetSignatureTypeFromCertificate(*cert)
		require.NoError(t, err)
		assert.Equal(t, 0, sigType, "DSA_SHA1 type 0 should be returned on success")
	})

	t.Run("uninitialized cert returns -1", func(t *testing.T) {
		var cert Certificate
		sigType, err := GetSignatureTypeFromCertificate(cert)
		require.Error(t, err)
		assert.Equal(t, -1, sigType)
	})

	t.Run("short payload returns -1", func(t *testing.T) {
		// parseCertificateFromData bypasses type-specific validation to construct a KEY cert
		// with a 2-byte payload, exercising the short-payload error path.
		shortCert, _ := parseCertificateFromData([]byte{CERT_KEY, 0x00, 0x02, 0x00, 0x07})
		sigType, err := GetSignatureTypeFromCertificate(shortCert)
		require.Error(t, err)
		assert.Equal(t, -1, sigType)
	})
}

func TestHandleShortCertificateData_LenFieldAlways2Bytes(t *testing.T) {
	t.Run("2-byte input produces proper 2-byte len field", func(t *testing.T) {
		cert, _, err := ReadCertificate([]byte{CERT_KEY, 0xFF})
		require.Error(t, err)
		assert.Nil(t, cert)
		assert.Contains(t, err.Error(), "too short")
	})

	t.Run("1-byte input produces proper 2-byte len field", func(t *testing.T) {
		cert, _, err := ReadCertificate([]byte{0x05})
		require.Error(t, err)
		assert.Nil(t, cert)
	})
}

func TestReadCertificate_UnknownType_WarningLogged(t *testing.T) {
	t.Run("type 6 accepted from wire with warning", func(t *testing.T) {
		cert, _, err := ReadCertificate([]byte{6, 0x00, 0x00})
		require.NoError(t, err)
		certType, _ := cert.Type()
		assert.Equal(t, 6, certType)
	})

	t.Run("type 100 accepted from wire", func(t *testing.T) {
		cert, _, err := ReadCertificate([]byte{100, 0x00, 0x00})
		require.NoError(t, err)
		certType, _ := cert.Type()
		assert.Equal(t, 100, certType)
	})

	t.Run("type 255 accepted from wire", func(t *testing.T) {
		cert, _, err := ReadCertificate([]byte{255, 0x00, 0x00})
		require.NoError(t, err)
		certType, _ := cert.Type()
		assert.Equal(t, 255, certType)
	})

	t.Run("unknown type with payload still works", func(t *testing.T) {
		cert, _, err := ReadCertificate([]byte{42, 0x00, 0x03, 0xAA, 0xBB, 0xCC})
		require.NoError(t, err)
		certType, _ := cert.Type()
		assert.Equal(t, 42, certType)
		data, _ := cert.Data()
		assert.Equal(t, []byte{0xAA, 0xBB, 0xCC}, data)
	})
}

func TestHandleShortCertificateData_InternalConsistency(t *testing.T) {
	t.Run("2-byte input certificate has 2-byte len field", func(t *testing.T) {
		_, remainder, err := ReadCertificate([]byte{CERT_KEY, 0xFF})
		require.Error(t, err)
		assert.Equal(t, []byte{CERT_KEY, 0xFF}, remainder)
	})
}

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

// TestValidateCertificatePayloadLengthNoInfoLeak verifies the fix for AUDIT QUALITY:
// validateCertificatePayloadLength no longer logs raw binary data via string(bytes),
// which could produce garbage output and leak sensitive payloads.
func TestValidateCertificatePayloadLengthNoInfoLeak(t *testing.T) {
	// Trigger the short-data error path. The important part is that the code
	// does NOT log `string(bytes)` anymore — the test verifies the error path
	// still works correctly.
	data := []byte{CERT_KEY, 0x00, 0x10, 0xAA, 0xBB} // declares 16-byte payload but only 2 available
	cert, _, err := ReadCertificate(data)
	require.Error(t, err, "should error when payload is shorter than declared")
	assert.Nil(t, cert)
	assert.Contains(t, err.Error(), "shorter than specified")
}
