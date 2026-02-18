package certificate

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// [BUG] Data aliasing: verify defensive copy in ReadCertificate
// =============================================================================

func TestDataAliasingDefensiveCopy(t *testing.T) {
	t.Run("mutating source bytes after ReadCertificate does not corrupt certificate", func(t *testing.T) {
		// Build a KEY certificate: type=5, length=4, payload=00 07 00 04
		src := []byte{CERT_KEY, 0x00, 0x04, 0x00, 0x07, 0x00, 0x04}
		cert, _, err := ReadCertificate(src)
		require.NoError(t, err)
		require.NotNil(t, cert)

		// Capture original values
		origType, _ := cert.Type()
		origLen, _ := cert.Length()
		origData, _ := cert.Data()
		origDataCopy := make([]byte, len(origData))
		copy(origDataCopy, origData)

		// Mutate every byte of the source buffer
		for i := range src {
			src[i] = 0xFF
		}

		// Verify certificate fields are unchanged
		newType, err := cert.Type()
		require.NoError(t, err)
		assert.Equal(t, origType, newType, "Type() should be unaffected by source mutation")

		newLen, err := cert.Length()
		require.NoError(t, err)
		assert.Equal(t, origLen, newLen, "Length() should be unaffected by source mutation")

		newData, err := cert.Data()
		require.NoError(t, err)
		assert.Equal(t, origDataCopy, newData, "Data() should be unaffected by source mutation")
	})

	t.Run("mutating source bytes does not affect NULL certificate", func(t *testing.T) {
		src := []byte{CERT_NULL, 0x00, 0x00}
		cert, _, err := ReadCertificate(src)
		require.NoError(t, err)
		require.NotNil(t, cert)

		src[0] = 0xFF
		src[1] = 0xFF

		newType, err := cert.Type()
		require.NoError(t, err)
		assert.Equal(t, CERT_NULL, newType)
	})
}

// =============================================================================
// [SPEC] SIGNED certificate payload length validation in constructor
// =============================================================================

func TestSignedCertificatePayloadValidation(t *testing.T) {
	t.Run("constructor accepts 40-byte SIGNED payload", func(t *testing.T) {
		payload := make([]byte, CERT_SIGNED_PAYLOAD_SHORT)
		cert, err := NewCertificateWithType(CERT_SIGNED, payload)
		require.NoError(t, err)
		require.NotNil(t, cert)

		certType, _ := cert.Type()
		assert.Equal(t, CERT_SIGNED, certType)
		certLen, _ := cert.Length()
		assert.Equal(t, 40, certLen)
	})

	t.Run("constructor accepts 72-byte SIGNED payload", func(t *testing.T) {
		payload := make([]byte, CERT_SIGNED_PAYLOAD_LONG)
		cert, err := NewCertificateWithType(CERT_SIGNED, payload)
		require.NoError(t, err)
		require.NotNil(t, cert)

		certLen, _ := cert.Length()
		assert.Equal(t, 72, certLen)
	})

	t.Run("constructor rejects 0-byte SIGNED payload", func(t *testing.T) {
		_, err := NewCertificateWithType(CERT_SIGNED, []byte{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "SIGNED certificates must have payload of")
	})

	t.Run("constructor rejects 1-byte SIGNED payload", func(t *testing.T) {
		_, err := NewCertificateWithType(CERT_SIGNED, []byte{0x01})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "SIGNED certificates must have payload of")
	})

	t.Run("constructor rejects 39-byte SIGNED payload", func(t *testing.T) {
		_, err := NewCertificateWithType(CERT_SIGNED, make([]byte, 39))
		require.Error(t, err)
	})

	t.Run("constructor rejects 41-byte SIGNED payload", func(t *testing.T) {
		_, err := NewCertificateWithType(CERT_SIGNED, make([]byte, 41))
		require.Error(t, err)
	})

	t.Run("constructor rejects 71-byte SIGNED payload", func(t *testing.T) {
		_, err := NewCertificateWithType(CERT_SIGNED, make([]byte, 71))
		require.Error(t, err)
	})

	t.Run("constructor rejects 73-byte SIGNED payload", func(t *testing.T) {
		_, err := NewCertificateWithType(CERT_SIGNED, make([]byte, 73))
		require.Error(t, err)
	})

	t.Run("ReadCertificate still accepts non-conforming SIGNED from wire (lenient parsing)", func(t *testing.T) {
		// Wire data with SIGNED type and 2-byte payload (non-conforming but parseable)
		wireData := []byte{CERT_SIGNED, 0x00, 0x02, 0xAA, 0xBB}
		cert, _, err := ReadCertificate(wireData)
		// ReadCertificate only warns, does not reject
		require.NoError(t, err)
		require.NotNil(t, cert)
		certType, _ := cert.Type()
		assert.Equal(t, CERT_SIGNED, certType)
	})
}

// =============================================================================
// [SPEC] HIDDEN certificate payload validation in constructor
// =============================================================================

func TestHiddenCertificatePayloadValidation(t *testing.T) {
	t.Run("constructor accepts empty HIDDEN payload", func(t *testing.T) {
		cert, err := NewCertificateWithType(CERT_HIDDEN, []byte{})
		require.NoError(t, err)
		require.NotNil(t, cert)
	})

	t.Run("constructor rejects non-empty HIDDEN payload", func(t *testing.T) {
		_, err := NewCertificateWithType(CERT_HIDDEN, []byte{0x01})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "HIDDEN certificates must have empty payload")
	})
}

// =============================================================================
// [GAP] length() optimized — no allocation
// =============================================================================

func TestLengthOptimized(t *testing.T) {
	t.Run("length equals CERT_MIN_SIZE for NULL cert", func(t *testing.T) {
		cert := NewCertificate()
		assert.Equal(t, CERT_MIN_SIZE, cert.length())
	})

	t.Run("length equals CERT_MIN_SIZE + payload for KEY cert", func(t *testing.T) {
		payload := []byte{0x00, 0x07, 0x00, 0x04}
		cert, err := NewCertificateWithType(CERT_KEY, payload)
		require.NoError(t, err)
		assert.Equal(t, CERT_MIN_SIZE+len(payload), cert.length())
	})

	t.Run("length matches Bytes length", func(t *testing.T) {
		payload := make([]byte, CERT_SIGNED_PAYLOAD_SHORT)
		cert, err := NewCertificateWithType(CERT_SIGNED, payload)
		require.NoError(t, err)
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

// =============================================================================
// [GAP] KEY certificate payload excess is not validated
// =============================================================================

func TestKeyCertificatePayloadMinimum(t *testing.T) {
	t.Run("KEY cert with exactly 4 bytes payload accepted", func(t *testing.T) {
		payload := []byte{0x00, 0x07, 0x00, 0x04}
		cert, err := NewCertificateWithType(CERT_KEY, payload)
		require.NoError(t, err)
		require.NotNil(t, cert)
	})

	t.Run("KEY cert with excess key data accepted", func(t *testing.T) {
		payload := make([]byte, 100) // 4 bytes type fields + 96 bytes excess
		payload[1] = 0x07            // signing type Ed25519
		payload[3] = 0x04            // crypto type X25519
		cert, err := NewCertificateWithType(CERT_KEY, payload)
		require.NoError(t, err)
		require.NotNil(t, cert)
	})

	t.Run("ReadCertificate warns on KEY cert with <4 byte payload", func(t *testing.T) {
		// KEY cert with only 2 bytes payload
		wireData := []byte{CERT_KEY, 0x00, 0x02, 0x00, 0x07}
		cert, _, err := ReadCertificate(wireData)
		// Warning only, still parses
		require.NoError(t, err)
		require.NotNil(t, cert)
	})
}

// =============================================================================
// [GAP] Type asymmetry between parsing and construction
// =============================================================================

func TestTypeAsymmetry(t *testing.T) {
	t.Run("constructor rejects unknown types", func(t *testing.T) {
		for _, invalidType := range []uint8{6, 7, 100, 200, 255} {
			_, err := NewCertificateWithType(invalidType, []byte{})
			require.Error(t, err, "type %d should be rejected by constructor", invalidType)
		}
	})

	t.Run("parser accepts any type byte 0-255", func(t *testing.T) {
		for _, typeVal := range []byte{0, 5, 6, 100, 255} {
			wireData := []byte{typeVal, 0x00, 0x00}
			cert, _, err := ReadCertificate(wireData)
			require.NoError(t, err, "type %d should be accepted by parser", typeVal)
			require.NotNil(t, cert)

			ct, err := cert.Type()
			require.NoError(t, err)
			assert.Equal(t, int(typeVal), ct)
		}
	})
}

// =============================================================================
// [TEST] Bytes() vs RawBytes() behavioral difference
// =============================================================================

func TestBytesVsRawBytes(t *testing.T) {
	t.Run("identical when payload matches declared length", func(t *testing.T) {
		payload := []byte{0x00, 0x07, 0x00, 0x04}
		cert, err := NewCertificateWithType(CERT_KEY, payload)
		require.NoError(t, err)

		assert.Equal(t, cert.Bytes(), cert.RawBytes(),
			"Bytes() and RawBytes() should be identical when payload == declared length")
	})

	t.Run("differ when payload has excess data", func(t *testing.T) {
		// Construct via ReadCertificate with excess payload
		// Type=KEY, declared length=2, actual payload=4 bytes
		wireData := []byte{CERT_KEY, 0x00, 0x02, 0x00, 0x07, 0x00, 0x04}
		cert, _, err := ReadCertificate(wireData)
		require.NoError(t, err)
		require.NotNil(t, cert)

		bytesResult := cert.Bytes()
		rawBytesResult := cert.RawBytes()

		// Bytes() trims to declared length (2 bytes of payload)
		assert.Equal(t, CERT_MIN_SIZE+2, len(bytesResult),
			"Bytes() should trim payload to declared length")

		// RawBytes() includes all payload (4 bytes)
		assert.Equal(t, CERT_MIN_SIZE+4, len(rawBytesResult),
			"RawBytes() should include all payload including excess")

		// RawBytes should be longer
		assert.Greater(t, len(rawBytesResult), len(bytesResult),
			"RawBytes() should be longer than Bytes() when there is excess data")
	})

	t.Run("both nil on invalid certificate", func(t *testing.T) {
		var cert Certificate
		assert.Nil(t, cert.Bytes())
		assert.Nil(t, cert.RawBytes())
	})
}

// =============================================================================
// [TEST] ReadCertificate benchmark
// =============================================================================

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

// =============================================================================
// [QUALITY] handleEmptyCertificateData / handleShortCertificateData length field
// =============================================================================

func TestErrorPathLengthFieldIs2Bytes(t *testing.T) {
	// These error paths still construct partial certificates internally.
	// We verify through ReadCertificate that errors are correctly returned.
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

// =============================================================================
// [QUALITY] GetSignatureTypeFromCertificate returns CERT_EMPTY_PAYLOAD_SIZE on error
// =============================================================================

func TestGetSignatureTypeErrorSentinel(t *testing.T) {
	t.Run("error return value is 0 which is also valid DSA_SHA1 type", func(t *testing.T) {
		// This documents the known ambiguity: error return value 0 matches DSA_SHA1
		cert, err := NewCertificateWithType(CERT_NULL, []byte{})
		require.NoError(t, err)

		sigType, err := GetSignatureTypeFromCertificate(*cert)
		require.Error(t, err, "should error for non-KEY certificate")
		assert.Equal(t, CERT_EMPTY_PAYLOAD_SIZE, sigType,
			"error sentinel value is CERT_EMPTY_PAYLOAD_SIZE (0)")

		// Callers MUST check the error - the return value alone is ambiguous
		assert.NotNil(t, err, "callers must check error, not just return value")
	})

	t.Run("GetCryptoTypeFromCertificate returns 0 on error", func(t *testing.T) {
		cert, err := NewCertificateWithType(CERT_NULL, []byte{})
		require.NoError(t, err)

		cryptoType, err := GetCryptoTypeFromCertificate(*cert)
		require.Error(t, err)
		assert.Equal(t, 0, cryptoType)
	})
}

// =============================================================================
// [QUALITY] Receiver consistency check - all pointer receivers
// =============================================================================

func TestAllMethodsUsePointerReceivers(t *testing.T) {
	// This test verifies that calling all methods on a pointer does not panic
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
