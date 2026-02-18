package certificate

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Finding 1: NewCertificate() produces invalid 2-byte serialization
// =============================================================================

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

// =============================================================================
// Finding 2: BuildKeyTypePayload silently wraps negative values
// =============================================================================

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

	t.Run("both negative rejected", func(t *testing.T) {
		_, err := BuildKeyTypePayload(-1, -1)
		require.Error(t, err)
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

// =============================================================================
// Finding 3: Bytes(), RawBytes(), ExcessBytes(), length() panic on nil receiver
// =============================================================================

func TestNilReceiverSafety(t *testing.T) {
	var cert *Certificate

	t.Run("Bytes returns nil on nil receiver", func(t *testing.T) {
		assert.NotPanics(t, func() {
			result := cert.Bytes()
			assert.Nil(t, result)
		})
	})

	t.Run("RawBytes returns nil on nil receiver", func(t *testing.T) {
		assert.NotPanics(t, func() {
			result := cert.RawBytes()
			assert.Nil(t, result)
		})
	})

	t.Run("ExcessBytes returns nil on nil receiver", func(t *testing.T) {
		assert.NotPanics(t, func() {
			result := cert.ExcessBytes()
			assert.Nil(t, result)
		})
	})

	t.Run("length returns 0 on nil receiver", func(t *testing.T) {
		assert.NotPanics(t, func() {
			result := cert.length()
			assert.Equal(t, 0, result)
		})
	})
}

func TestZeroValueReceiverSafety(t *testing.T) {
	var cert Certificate

	t.Run("Bytes returns nil on zero-value receiver", func(t *testing.T) {
		assert.NotPanics(t, func() {
			result := cert.Bytes()
			assert.Nil(t, result)
		})
	})

	t.Run("RawBytes returns nil on zero-value receiver", func(t *testing.T) {
		assert.NotPanics(t, func() {
			result := cert.RawBytes()
			assert.Nil(t, result)
		})
	})

	t.Run("ExcessBytes returns nil on zero-value receiver", func(t *testing.T) {
		assert.NotPanics(t, func() {
			result := cert.ExcessBytes()
			assert.Nil(t, result)
		})
	})

	t.Run("length returns 0 on zero-value receiver", func(t *testing.T) {
		assert.NotPanics(t, func() {
			result := cert.length()
			assert.Equal(t, 0, result)
		})
	})
}

// =============================================================================
// Finding 4: No enforcement of type-specific payload lengths during parsing
// =============================================================================

func TestTypeSpecificPayloadValidation(t *testing.T) {
	t.Run("NULL cert with payload logs warning but parses", func(t *testing.T) {
		// NULL cert type (0) with 2-byte payload - should parse but warn
		certBytes := []byte{CERT_NULL, 0x00, 0x02, 0xAA, 0xBB}
		cert, _, err := ReadCertificate(certBytes)
		// Parses successfully (warning only, not error)
		require.NoError(t, err)
		require.NotNil(t, cert)
		certType, _ := cert.Type()
		assert.Equal(t, CERT_NULL, certType)
	})

	t.Run("HIDDEN cert with payload logs warning but parses", func(t *testing.T) {
		certBytes := []byte{CERT_HIDDEN, 0x00, 0x02, 0xAA, 0xBB}
		cert, _, err := ReadCertificate(certBytes)
		require.NoError(t, err)
		require.NotNil(t, cert)
		certType, _ := cert.Type()
		assert.Equal(t, CERT_HIDDEN, certType)
	})

	t.Run("KEY cert with valid payload parses", func(t *testing.T) {
		certBytes := []byte{CERT_KEY, 0x00, 0x04, 0x00, 0x07, 0x00, 0x04}
		cert, _, err := ReadCertificate(certBytes)
		require.NoError(t, err)
		require.NotNil(t, cert)
		certType, _ := cert.Type()
		assert.Equal(t, CERT_KEY, certType)
	})

	t.Run("KEY cert with insufficient payload logs warning", func(t *testing.T) {
		// KEY cert with only 2 bytes payload (minimum is 4)
		certBytes := []byte{CERT_KEY, 0x00, 0x02, 0x00, 0x07}
		cert, _, err := ReadCertificate(certBytes)
		// Still parses (warning only) - consumers should validate
		require.NoError(t, err)
		require.NotNil(t, cert)
	})

	t.Run("valid NULL cert with empty payload", func(t *testing.T) {
		certBytes := []byte{CERT_NULL, 0x00, 0x00}
		cert, _, err := ReadCertificate(certBytes)
		require.NoError(t, err)
		require.NotNil(t, cert)
	})
}

// =============================================================================
// Finding 5: normalizeErrorConditions is dead code (removed)
// Verify ReadCertificate still works correctly without it
// =============================================================================

func TestReadCertificateWithoutNormalize(t *testing.T) {
	t.Run("valid cert parses without error", func(t *testing.T) {
		certBytes := []byte{CERT_NULL, 0x00, 0x00}
		cert, remainder, err := ReadCertificate(certBytes)
		require.NoError(t, err)
		require.NotNil(t, cert)
		assert.Equal(t, 0, len(remainder))
	})

	t.Run("cert with excess data parses correctly", func(t *testing.T) {
		certBytes := []byte{CERT_SIGNED, 0x00, 0x02, 0xAA, 0xBB, 0xCC, 0xDD}
		cert, remainder, err := ReadCertificate(certBytes)
		require.NoError(t, err)
		require.NotNil(t, cert)
		assert.Equal(t, []byte{0xCC, 0xDD}, remainder)
	})

	t.Run("short data returns error", func(t *testing.T) {
		certBytes := []byte{CERT_NULL, 0x00, 0x05, 0xAA}
		cert, _, err := ReadCertificate(certBytes)
		require.Error(t, err)
		assert.Nil(t, cert)
	})
}

// =============================================================================
// Finding 6: Missing GetCryptoTypeFromCertificate function
// =============================================================================

func TestGetCryptoTypeFromCertificate(t *testing.T) {
	t.Run("valid KEY cert returns correct crypto type", func(t *testing.T) {
		// Create KEY cert with signing=7 (Ed25519), crypto=4 (X25519)
		payload := []byte{0x00, 0x07, 0x00, 0x04}
		cert, err := NewCertificateWithType(CERT_KEY, payload)
		require.NoError(t, err)

		cryptoType, err := GetCryptoTypeFromCertificate(*cert)
		require.NoError(t, err)
		assert.Equal(t, 4, cryptoType)
	})

	t.Run("valid KEY cert with zero types", func(t *testing.T) {
		payload := []byte{0x00, 0x00, 0x00, 0x00}
		cert, err := NewCertificateWithType(CERT_KEY, payload)
		require.NoError(t, err)

		cryptoType, err := GetCryptoTypeFromCertificate(*cert)
		require.NoError(t, err)
		assert.Equal(t, 0, cryptoType)
	})

	t.Run("NULL cert returns error", func(t *testing.T) {
		cert, err := NewCertificateWithType(CERT_NULL, []byte{})
		require.NoError(t, err)

		_, err = GetCryptoTypeFromCertificate(*cert)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unexpected certificate type")
	})

	t.Run("uninitialized cert returns error", func(t *testing.T) {
		var cert Certificate
		_, err := GetCryptoTypeFromCertificate(cert)
		require.Error(t, err)
	})

	t.Run("symmetric with GetSignatureTypeFromCertificate", func(t *testing.T) {
		payload := []byte{0x00, 0x07, 0x00, 0x04}
		cert, err := NewCertificateWithType(CERT_KEY, payload)
		require.NoError(t, err)

		sigType, err := GetSignatureTypeFromCertificate(*cert)
		require.NoError(t, err)
		assert.Equal(t, 7, sigType)

		cryptoType, err := GetCryptoTypeFromCertificate(*cert)
		require.NoError(t, err)
		assert.Equal(t, 4, cryptoType)
	})
}

// =============================================================================
// Finding 8: Type() validation inconsistency between creation and parsing
// =============================================================================

func TestTypeValidationAsymmetry(t *testing.T) {
	t.Run("creation rejects type 6", func(t *testing.T) {
		_, err := NewCertificateWithType(6, []byte{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid certificate type")
	})

	t.Run("parsing accepts type 6 from bytes", func(t *testing.T) {
		// Type 6 is not in the enum but should parse from bytes
		certBytes := []byte{6, 0x00, 0x00}
		cert, _, err := ReadCertificate(certBytes)
		require.NoError(t, err)
		require.NotNil(t, cert)

		certType, err := cert.Type()
		require.NoError(t, err)
		assert.Equal(t, 6, certType)
	})

	t.Run("parsing accepts type 255 from bytes", func(t *testing.T) {
		certBytes := []byte{255, 0x00, 0x00}
		cert, _, err := ReadCertificate(certBytes)
		require.NoError(t, err)
		require.NotNil(t, cert)

		certType, err := cert.Type()
		require.NoError(t, err)
		assert.Equal(t, 255, certType)
	})
}

// =============================================================================
// Finding 9: No tests for GetSignatureTypeFromCertificate
// =============================================================================

func TestGetSignatureTypeFromCertificate(t *testing.T) {
	t.Run("valid KEY cert extracts Ed25519", func(t *testing.T) {
		payload := []byte{0x00, 0x07, 0x00, 0x04}
		cert, err := NewCertificateWithType(CERT_KEY, payload)
		require.NoError(t, err)

		sigType, err := GetSignatureTypeFromCertificate(*cert)
		require.NoError(t, err)
		assert.Equal(t, 7, sigType)
	})

	t.Run("valid KEY cert extracts DSA (type 0)", func(t *testing.T) {
		payload := []byte{0x00, 0x00, 0x00, 0x00}
		cert, err := NewCertificateWithType(CERT_KEY, payload)
		require.NoError(t, err)

		sigType, err := GetSignatureTypeFromCertificate(*cert)
		require.NoError(t, err)
		assert.Equal(t, 0, sigType)
	})

	t.Run("non-KEY cert returns error", func(t *testing.T) {
		cert, err := NewCertificateWithType(CERT_NULL, []byte{})
		require.NoError(t, err)

		_, err = GetSignatureTypeFromCertificate(*cert)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unexpected certificate type: 0")
	})

	t.Run("SIGNED cert returns error", func(t *testing.T) {
		cert, err := NewCertificateWithType(CERT_SIGNED, make([]byte, CERT_SIGNED_PAYLOAD_SHORT))
		require.NoError(t, err)

		_, err = GetSignatureTypeFromCertificate(*cert)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unexpected certificate type: 3")
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
		cert, err := NewCertificateWithType(CERT_KEY, payload)
		require.NoError(t, err)

		sigType, err := GetSignatureTypeFromCertificate(*cert)
		require.NoError(t, err)
		assert.Equal(t, 65535, sigType)
	})
}

// =============================================================================
// Finding 10: No test for NewCertificate() round-trip serialization
// =============================================================================

func TestNewCertificateRoundTrip(t *testing.T) {
	t.Run("NewCertificate serializes and deserializes correctly", func(t *testing.T) {
		cert := NewCertificate()
		b := cert.Bytes()
		assert.Equal(t, CERT_MIN_SIZE, len(b),
			"NewCertificate().Bytes() should be exactly CERT_MIN_SIZE")

		parsed, remainder, err := ReadCertificate(b)
		require.NoError(t, err)
		require.NotNil(t, parsed)
		assert.Empty(t, remainder)

		origType, _ := cert.Type()
		parsedType, _ := parsed.Type()
		assert.Equal(t, origType, parsedType)

		origLen, _ := cert.Length()
		parsedLen, _ := parsed.Length()
		assert.Equal(t, origLen, parsedLen)
	})
}

// =============================================================================
// Finding 13: GetSignatureTypeFromCertificate uses misleading constant as slice index
// Verify that the fix works correctly with various payload sizes
// =============================================================================

func TestSliceIndexCorrectness(t *testing.T) {
	t.Run("signature type extraction with 4-byte payload", func(t *testing.T) {
		payload := []byte{0x00, 0x07, 0x00, 0x04}
		cert, err := NewCertificateWithType(CERT_KEY, payload)
		require.NoError(t, err)

		sigType, err := GetSignatureTypeFromCertificate(*cert)
		require.NoError(t, err)
		assert.Equal(t, 7, sigType)
	})

	t.Run("crypto type extraction with 4-byte payload", func(t *testing.T) {
		payload := []byte{0x00, 0x07, 0x00, 0x04}
		cert, err := NewCertificateWithType(CERT_KEY, payload)
		require.NoError(t, err)

		cryptoType, err := GetCryptoTypeFromCertificate(*cert)
		require.NoError(t, err)
		assert.Equal(t, 4, cryptoType)
	})

	t.Run("extraction with larger payload (extra padding)", func(t *testing.T) {
		// KEY certificate with extra padding bytes (common in real-world certs)
		payload := []byte{0x00, 0x07, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00}
		cert, err := NewCertificateWithType(CERT_KEY, payload)
		require.NoError(t, err)

		sigType, err := GetSignatureTypeFromCertificate(*cert)
		require.NoError(t, err)
		assert.Equal(t, 7, sigType)

		cryptoType, err := GetCryptoTypeFromCertificate(*cert)
		require.NoError(t, err)
		assert.Equal(t, 4, cryptoType)
	})
}

// =============================================================================
// Fuzz test for ReadCertificate
// =============================================================================

func FuzzReadCertificate(f *testing.F) {
	// Seed corpus
	f.Add([]byte{})
	f.Add([]byte{0x00})
	f.Add([]byte{0x00, 0x00})
	f.Add([]byte{0x00, 0x00, 0x00})
	f.Add([]byte{0x05, 0x00, 0x04, 0x00, 0x07, 0x00, 0x04})
	f.Add([]byte{0x00, 0x00, 0x01, 0xFF})
	f.Add([]byte{0xFF, 0xFF, 0xFF})
	f.Add([]byte{0x03, 0x00, 0x28}) // SIGNED with 40-byte length

	f.Fuzz(func(t *testing.T, data []byte) {
		cert, remainder, err := ReadCertificate(data)
		if err != nil {
			// On error, cert should be nil and remainder should be original data
			assert.Nil(t, cert)
			assert.Equal(t, data, remainder)
			return
		}
		// On success, cert should be valid
		require.NotNil(t, cert)
		assert.True(t, cert.IsValid())

		// Type should be in valid range
		certType, typeErr := cert.Type()
		assert.NoError(t, typeErr)
		assert.GreaterOrEqual(t, certType, 0)
		assert.LessOrEqual(t, certType, 255)
	})
}
