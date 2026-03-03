package offline_signature

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"

	"github.com/go-i2p/common/key_certificate"
	"github.com/go-i2p/common/signature"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =========================================================================
// ReadOfflineSignature Tests
// =========================================================================

func TestReadOfflineSignatureValidEdDSA(t *testing.T) {
	expires := uint32(1735689600)
	transientSigType := uint16(key_certificate.KEYCERT_SIGN_ED25519)
	transientKeySize := key_certificate.KEYCERT_SIGN_ED25519_SIZE
	destSigType := uint16(signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519)
	signatureSize := signature.EdDSA_SHA512_Ed25519_SIZE

	data := make([]byte, EXPIRES_SIZE+SIGTYPE_SIZE+transientKeySize+signatureSize)
	binary.BigEndian.PutUint32(data[0:4], expires)
	binary.BigEndian.PutUint16(data[4:6], transientSigType)
	for i := 0; i < transientKeySize; i++ {
		data[6+i] = byte(i)
	}
	sigOffset := 6 + transientKeySize
	for i := 0; i < signatureSize; i++ {
		data[sigOffset+i] = byte(0xFF - i)
	}
	extraData := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	data = append(data, extraData...)

	offlineSig, remainder, err := ReadOfflineSignature(data, destSigType)

	assert.NoError(t, err, "should parse valid Ed25519 OfflineSignature without error")
	assert.Equal(t, expires, offlineSig.Expires(), "expires timestamp should match")
	assert.Equal(t, transientSigType, offlineSig.TransientSigType(), "transient signature type should match")
	assert.Equal(t, transientKeySize, len(offlineSig.TransientPublicKey()), "transient key size should match")
	assert.Equal(t, signatureSize, len(offlineSig.Signature()), "signature size should match")
	assert.Equal(t, destSigType, offlineSig.DestinationSigType(), "destination signature type should match")
	assert.Equal(t, extraData, remainder, "remainder should contain extra data")
}

func TestReadOfflineSignatureVariousSignatureTypes(t *testing.T) {
	testCases := []struct {
		name               string
		transientSigType   uint16
		destinationSigType uint16
		transientKeySize   int
		signatureSize      int
	}{
		{
			name:               "DSA_SHA1_transient_DSA_destination",
			transientSigType:   key_certificate.KEYCERT_SIGN_DSA_SHA1,
			destinationSigType: signature.SIGNATURE_TYPE_DSA_SHA1,
			transientKeySize:   key_certificate.KEYCERT_SIGN_DSA_SHA1_SIZE,
			signatureSize:      signature.DSA_SHA1_SIZE,
		},
		{
			name:               "P256_transient_Ed25519_destination",
			transientSigType:   key_certificate.KEYCERT_SIGN_P256,
			destinationSigType: signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519,
			transientKeySize:   key_certificate.KEYCERT_SIGN_P256_SIZE,
			signatureSize:      signature.EdDSA_SHA512_Ed25519_SIZE,
		},
		{
			name:               "RSA4096_transient_Ed25519_destination",
			transientSigType:   key_certificate.KEYCERT_SIGN_RSA4096,
			destinationSigType: signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519,
			transientKeySize:   key_certificate.KEYCERT_SIGN_RSA4096_SIZE,
			signatureSize:      signature.EdDSA_SHA512_Ed25519_SIZE,
		},
		{
			name:               "RedDSA_transient_Ed25519_destination",
			transientSigType:   key_certificate.KEYCERT_SIGN_REDDSA_ED25519,
			destinationSigType: signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519,
			transientKeySize:   key_certificate.KEYCERT_SIGN_ED25519_SIZE,
			signatureSize:      signature.EdDSA_SHA512_Ed25519_SIZE,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			expires := uint32(1735689600)
			data := make([]byte, EXPIRES_SIZE+SIGTYPE_SIZE+tc.transientKeySize+tc.signatureSize)
			binary.BigEndian.PutUint32(data[0:4], expires)
			binary.BigEndian.PutUint16(data[4:6], tc.transientSigType)

			offlineSig, remainder, err := ReadOfflineSignature(data, tc.destinationSigType)

			assert.NoError(t, err, "should parse OfflineSignature without error")
			assert.Equal(t, expires, offlineSig.Expires())
			assert.Equal(t, tc.transientSigType, offlineSig.TransientSigType())
			assert.Equal(t, tc.transientKeySize, len(offlineSig.TransientPublicKey()))
			assert.Equal(t, tc.signatureSize, len(offlineSig.Signature()))
			assert.Empty(t, remainder, "should have no remainder")
		})
	}
}

// =========================================================================
// NewOfflineSignature Tests
// =========================================================================

func TestNewOfflineSignatureValid(t *testing.T) {
	expires := uint32(1735689600)
	transientSigType := uint16(key_certificate.KEYCERT_SIGN_ED25519)
	transientKey := make([]byte, key_certificate.KEYCERT_SIGN_ED25519_SIZE)
	sig := make([]byte, signature.EdDSA_SHA512_Ed25519_SIZE)
	destSigType := uint16(signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519)

	offlineSig, err := NewOfflineSignature(expires, transientSigType, transientKey, sig, destSigType)

	assert.NoError(t, err, "should create OfflineSignature without error")
	assert.Equal(t, expires, offlineSig.Expires())
	assert.Equal(t, transientSigType, offlineSig.TransientSigType())
	assert.Equal(t, destSigType, offlineSig.DestinationSigType())
}

func TestNewOfflineSignatureInvalidSizes(t *testing.T) {
	expires := uint32(1735689600)

	testCases := []struct {
		name               string
		transientSigType   uint16
		transientKeySize   int
		destinationSigType uint16
		signatureSize      int
	}{
		{
			name:               "wrong_transient_key_size",
			transientSigType:   key_certificate.KEYCERT_SIGN_ED25519,
			transientKeySize:   16,
			destinationSigType: signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519,
			signatureSize:      signature.EdDSA_SHA512_Ed25519_SIZE,
		},
		{
			name:               "wrong_signature_size",
			transientSigType:   key_certificate.KEYCERT_SIGN_ED25519,
			transientKeySize:   key_certificate.KEYCERT_SIGN_ED25519_SIZE,
			destinationSigType: signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519,
			signatureSize:      32,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			transientKey := make([]byte, tc.transientKeySize)
			sig := make([]byte, tc.signatureSize)

			_, err := NewOfflineSignature(expires, tc.transientSigType, transientKey, sig, tc.destinationSigType)

			assert.Error(t, err, "should return error for mismatched sizes")
		})
	}
}

func TestNewOfflineSignatureDefensiveCopy(t *testing.T) {
	transientKey := make([]byte, key_certificate.KEYCERT_SIGN_ED25519_SIZE)
	sig := make([]byte, signature.EdDSA_SHA512_Ed25519_SIZE)
	for i := range transientKey {
		transientKey[i] = byte(i)
	}
	for i := range sig {
		sig[i] = byte(0xFF - i)
	}

	offlineSig, err := NewOfflineSignature(
		uint32(1735689600),
		key_certificate.KEYCERT_SIGN_ED25519,
		transientKey, sig,
		signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519,
	)
	require.NoError(t, err)

	// Mutate the original input slices
	transientKey[0] = 0xFF
	sig[0] = 0x00

	// The struct's internal data should be unchanged
	assert.Equal(t, byte(0), offlineSig.TransientPublicKey()[0],
		"transient key should not be affected by caller mutation")
	assert.Equal(t, byte(0xFF), offlineSig.Signature()[0],
		"signature should not be affected by caller mutation")
}

// =========================================================================
// Accessor Tests
// =========================================================================

func TestOfflineSignatureAccessorsCopy(t *testing.T) {
	transientKey := make([]byte, key_certificate.KEYCERT_SIGN_ED25519_SIZE)
	sig := make([]byte, signature.EdDSA_SHA512_Ed25519_SIZE)
	for i := range transientKey {
		transientKey[i] = byte(i)
	}
	for i := range sig {
		sig[i] = byte(0xFF - i)
	}

	offlineSig, err := NewOfflineSignature(
		uint32(1735689600),
		key_certificate.KEYCERT_SIGN_ED25519,
		transientKey, sig,
		signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519,
	)
	assert.NoError(t, err)

	keyCopy := offlineSig.TransientPublicKey()
	sigCopy := offlineSig.Signature()
	keyCopy[0] = 0xFF
	sigCopy[0] = 0x00

	assert.Equal(t, byte(0), offlineSig.TransientPublicKey()[0], "transient key should not be modified")
	assert.Equal(t, byte(0xFF), offlineSig.Signature()[0], "signature should not be modified")
}

func TestOfflineSignatureLenConsistency(t *testing.T) {
	transientKey := make([]byte, key_certificate.KEYCERT_SIGN_ED25519_SIZE)
	sig := make([]byte, signature.EdDSA_SHA512_Ed25519_SIZE)

	offlineSig, err := NewOfflineSignature(
		uint32(1735689600),
		key_certificate.KEYCERT_SIGN_ED25519,
		transientKey, sig,
		signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519,
	)
	assert.NoError(t, err)
	assert.Equal(t, offlineSig.Len(), len(offlineSig.Bytes()), "Len() should match Bytes() length")
}

func TestOfflineSignatureExpiresTime(t *testing.T) {
	expectedTime := time.Date(2025, time.January, 1, 0, 0, 0, 0, time.UTC)
	expires := uint32(expectedTime.Unix())

	transientKey := make([]byte, key_certificate.KEYCERT_SIGN_ED25519_SIZE)
	sig := make([]byte, signature.EdDSA_SHA512_Ed25519_SIZE)

	offlineSig, err := NewOfflineSignature(
		expires,
		key_certificate.KEYCERT_SIGN_ED25519,
		transientKey, sig,
		signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519,
	)
	assert.NoError(t, err)

	expiresTime := offlineSig.ExpiresTime()
	assert.Equal(t, expectedTime.Unix(), expiresTime.Unix(), "time conversion should match")
}

func TestOfflineSignatureExpiresDate(t *testing.T) {
	expires := uint32(1735689600)
	transientKey := make([]byte, key_certificate.KEYCERT_SIGN_ED25519_SIZE)
	sig := make([]byte, signature.EdDSA_SHA512_Ed25519_SIZE)

	offlineSig, err := NewOfflineSignature(
		expires,
		uint16(key_certificate.KEYCERT_SIGN_ED25519),
		transientKey, sig,
		uint16(signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519),
	)
	assert.NoError(t, err)

	i2pDate, err := offlineSig.ExpiresDate()
	assert.NoError(t, err, "should convert to I2P Date without error")

	expectedMilliseconds := uint64(expires) * 1000
	i2pBytes := i2pDate.Bytes()
	actualMilliseconds := binary.BigEndian.Uint64(i2pBytes)
	assert.Equal(t, expectedMilliseconds, actualMilliseconds, "I2P Date conversion should match")
}

func TestOfflineSignatureString(t *testing.T) {
	expires := uint32(1735689600)
	transientKey := make([]byte, key_certificate.KEYCERT_SIGN_ED25519_SIZE)
	sig := make([]byte, signature.EdDSA_SHA512_Ed25519_SIZE)

	offlineSig, err := NewOfflineSignature(
		expires,
		key_certificate.KEYCERT_SIGN_ED25519,
		transientKey, sig,
		signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519,
	)
	assert.NoError(t, err)

	str := offlineSig.String()
	assert.Contains(t, str, "OfflineSignature{")
	assert.Contains(t, str, "expires:")
	assert.Contains(t, str, "transient_sigtype:")
	assert.Contains(t, str, "signature_len:")
}

func TestOfflineSignatureIsExpired(t *testing.T) {
	transientKey := make([]byte, key_certificate.KEYCERT_SIGN_ED25519_SIZE)
	sig := make([]byte, signature.EdDSA_SHA512_Ed25519_SIZE)

	testCases := []struct {
		name     string
		expires  uint32
		expected bool
	}{
		{"expired_signature", uint32(time.Now().UTC().Add(-1 * time.Hour).Unix()), true},
		{"valid_signature", uint32(time.Now().UTC().Add(24 * time.Hour).Unix()), false},
		{"future_signature", uint32(time.Now().UTC().Add(365 * 24 * time.Hour).Unix()), false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			offlineSig, err := NewOfflineSignature(
				tc.expires,
				key_certificate.KEYCERT_SIGN_ED25519,
				transientKey, sig,
				signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519,
			)
			assert.NoError(t, err)
			assert.Equal(t, tc.expected, offlineSig.IsExpired(), "expiration status should match expected")
		})
	}
}

// =========================================================================
// SignedData Tests
// =========================================================================

func TestSignedData(t *testing.T) {
	expires := uint32(1735689600)
	transientKey := make([]byte, key_certificate.KEYCERT_SIGN_ED25519_SIZE)
	for i := range transientKey {
		transientKey[i] = byte(i + 1)
	}
	sig := make([]byte, signature.EdDSA_SHA512_Ed25519_SIZE)

	offlineSig, err := NewOfflineSignature(
		expires,
		key_certificate.KEYCERT_SIGN_ED25519,
		transientKey, sig,
		signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519,
	)
	require.NoError(t, err)

	signedData := offlineSig.SignedData()

	t.Run("correct_length", func(t *testing.T) {
		expected := EXPIRES_SIZE + SIGTYPE_SIZE + key_certificate.KEYCERT_SIGN_ED25519_SIZE
		assert.Equal(t, expected, len(signedData), "signed data length should be 4+2+32=38")
	})

	t.Run("expires_field", func(t *testing.T) {
		gotExpires := binary.BigEndian.Uint32(signedData[0:4])
		assert.Equal(t, expires, gotExpires, "expires should match")
	})

	t.Run("sigtype_field", func(t *testing.T) {
		gotSigtype := binary.BigEndian.Uint16(signedData[4:6])
		assert.Equal(t, uint16(key_certificate.KEYCERT_SIGN_ED25519), gotSigtype, "sigtype should match")
	})

	t.Run("transient_key_field", func(t *testing.T) {
		gotKey := signedData[6:]
		assert.Equal(t, transientKey, gotKey, "transient key bytes should match")
	})

	t.Run("different_key_types", func(t *testing.T) {
		dsaKey := make([]byte, key_certificate.KEYCERT_SIGN_DSA_SHA1_SIZE)
		dsaSig := make([]byte, signature.DSA_SHA1_SIZE)
		dsa, err := NewOfflineSignature(expires, key_certificate.KEYCERT_SIGN_DSA_SHA1, dsaKey, dsaSig, signature.SIGNATURE_TYPE_DSA_SHA1)
		require.NoError(t, err)
		sd := dsa.SignedData()
		assert.Equal(t, EXPIRES_SIZE+SIGTYPE_SIZE+key_certificate.KEYCERT_SIGN_DSA_SHA1_SIZE, len(sd))
	})
}

// =========================================================================
// Deterministic serialization
// =========================================================================

func TestOfflineSignatureBytesIdentical(t *testing.T) {
	transientKey := make([]byte, key_certificate.KEYCERT_SIGN_ED25519_SIZE)
	sig := make([]byte, signature.EdDSA_SHA512_Ed25519_SIZE)
	for i := range transientKey {
		transientKey[i] = byte(i)
	}
	for i := range sig {
		sig[i] = byte(0xFF - i)
	}

	offlineSig, err := NewOfflineSignature(
		uint32(1735689600),
		key_certificate.KEYCERT_SIGN_ED25519,
		transientKey, sig,
		signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519,
	)
	assert.NoError(t, err)

	bytes1 := offlineSig.Bytes()
	bytes2 := offlineSig.Bytes()
	bytes3 := offlineSig.Bytes()

	assert.True(t, bytes.Equal(bytes1, bytes2), "first and second serialization should be identical")
	assert.True(t, bytes.Equal(bytes2, bytes3), "second and third serialization should be identical")
}

func TestMaxSizeOfflineSignature(t *testing.T) {
	t.Run("rsa4096_transient_rsa4096_destination", func(t *testing.T) {
		expires := uint32(time.Now().UTC().Add(24 * time.Hour).Unix())
		transientKeySize := key_certificate.KEYCERT_SIGN_RSA4096_SIZE // 512 bytes
		sigSize := signature.RSA_SHA512_4096_SIZE                     // 512 bytes

		transientKey := make([]byte, transientKeySize)
		sig := make([]byte, sigSize)
		for i := range transientKey {
			transientKey[i] = byte(i)
		}
		for i := range sig {
			sig[i] = byte(0xFF - i)
		}

		offlineSig, err := NewOfflineSignature(
			expires,
			key_certificate.KEYCERT_SIGN_RSA4096,
			transientKey, sig,
			signature.SIGNATURE_TYPE_RSA_SHA512_4096,
		)
		require.NoError(t, err)

		expectedSize := EXPIRES_SIZE + SIGTYPE_SIZE + transientKeySize + sigSize
		assert.Equal(t, 1030, expectedSize, "RSA4096+RSA4096 should be 4+2+512+512=1030 bytes")
		assert.Equal(t, expectedSize, offlineSig.Len(), "Len() should match calculated size")
		assert.Equal(t, expectedSize, len(offlineSig.Bytes()), "Bytes() length should match")
	})

	t.Run("rsa4096_round_trip", func(t *testing.T) {
		expires := uint32(1735689600)
		transientKey := make([]byte, key_certificate.KEYCERT_SIGN_RSA4096_SIZE)
		sig := make([]byte, signature.RSA_SHA512_4096_SIZE)
		for i := range transientKey {
			transientKey[i] = byte(i)
		}
		for i := range sig {
			sig[i] = byte(0xAB ^ byte(i))
		}

		original, err := NewOfflineSignature(
			expires,
			key_certificate.KEYCERT_SIGN_RSA4096,
			transientKey, sig,
			signature.SIGNATURE_TYPE_RSA_SHA512_4096,
		)
		require.NoError(t, err)

		serialized := original.Bytes()
		parsed, remainder, err := ReadOfflineSignature(serialized, signature.SIGNATURE_TYPE_RSA_SHA512_4096)
		require.NoError(t, err)
		assert.Empty(t, remainder)

		assert.Equal(t, original.Expires(), parsed.Expires())
		assert.Equal(t, original.TransientSigType(), parsed.TransientSigType())
		assert.Equal(t, original.TransientPublicKey(), parsed.TransientPublicKey())
		assert.Equal(t, original.Signature(), parsed.Signature())
		assert.Equal(t, original.DestinationSigType(), parsed.DestinationSigType())
		assert.Equal(t, original.Len(), parsed.Len())
	})

	t.Run("rsa4096_validates_structure", func(t *testing.T) {
		expires := uint32(time.Now().UTC().Add(24 * time.Hour).Unix())
		transientKey := make([]byte, key_certificate.KEYCERT_SIGN_RSA4096_SIZE)
		sig := make([]byte, signature.RSA_SHA512_4096_SIZE)

		offlineSig, err := NewOfflineSignature(
			expires,
			key_certificate.KEYCERT_SIGN_RSA4096,
			transientKey, sig,
			signature.SIGNATURE_TYPE_RSA_SHA512_4096,
		)
		require.NoError(t, err)
		assert.NoError(t, offlineSig.ValidateStructure(), "RSA4096 OfflineSignature should pass structural validation")
	})
}

// =========================================================================
// computeSignedData Tests (QUALITY-1: single source of truth)
// =========================================================================

func TestComputeSignedDataEquivalence(t *testing.T) {
	// Verify that SignedData() method and CreateOfflineSignature use the same
	// computeSignedData function, producing identical byte sequences.
	expires := uint32(1735689600)
	sigtype := uint16(key_certificate.KEYCERT_SIGN_ED25519)
	transientKey := make([]byte, key_certificate.KEYCERT_SIGN_ED25519_SIZE)
	for i := range transientKey {
		transientKey[i] = byte(i + 1)
	}

	// Call computeSignedData directly
	direct := computeSignedData(expires, sigtype, transientKey)

	// Build an OfflineSignature and call SignedData()
	sig := make([]byte, signature.EdDSA_SHA512_Ed25519_SIZE)
	offlineSig, err := NewOfflineSignature(expires, sigtype, transientKey, sig,
		signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519)
	require.NoError(t, err)
	method := offlineSig.SignedData()

	assert.Equal(t, direct, method,
		"computeSignedData and SignedData() should produce identical byte sequences")
	assert.Equal(t, EXPIRES_SIZE+SIGTYPE_SIZE+len(transientKey), len(direct),
		"signed data length should be header + key size")
}

func TestComputeSignedDataFormat(t *testing.T) {
	expires := uint32(0x12345678)
	sigtype := uint16(key_certificate.KEYCERT_SIGN_P256)
	transientKey := make([]byte, key_certificate.KEYCERT_SIGN_P256_SIZE)
	for i := range transientKey {
		transientKey[i] = byte(i)
	}

	result := computeSignedData(expires, sigtype, transientKey)

	// Verify expires (big-endian)
	assert.Equal(t, byte(0x12), result[0])
	assert.Equal(t, byte(0x34), result[1])
	assert.Equal(t, byte(0x56), result[2])
	assert.Equal(t, byte(0x78), result[3])

	// Verify sigtype (big-endian)
	parsedSigtype := binary.BigEndian.Uint16(result[4:6])
	assert.Equal(t, sigtype, parsedSigtype)

	// Verify transient key
	assert.True(t, bytes.Equal(transientKey, result[6:]))
}

// =========================================================================
// SigningPublicKeySize Delegation Tests (QUALITY-2)
// =========================================================================

func TestSigningPublicKeySizeDelegation(t *testing.T) {
	// Verify that SigningPublicKeySize returns correct values for all supported types
	// by cross-referencing with key_certificate.GetSigningKeySize (the source of truth).
	testCases := []struct {
		name     string
		sigType  uint16
		expected int
	}{
		{"DSA_SHA1", key_certificate.KEYCERT_SIGN_DSA_SHA1, key_certificate.KEYCERT_SIGN_DSA_SHA1_SIZE},
		{"P256", key_certificate.KEYCERT_SIGN_P256, key_certificate.KEYCERT_SIGN_P256_SIZE},
		{"P384", key_certificate.KEYCERT_SIGN_P384, key_certificate.KEYCERT_SIGN_P384_SIZE},
		{"P521", key_certificate.KEYCERT_SIGN_P521, key_certificate.KEYCERT_SIGN_P521_SIZE},
		{"RSA2048", key_certificate.KEYCERT_SIGN_RSA2048, key_certificate.KEYCERT_SIGN_RSA2048_SIZE},
		{"RSA3072", key_certificate.KEYCERT_SIGN_RSA3072, key_certificate.KEYCERT_SIGN_RSA3072_SIZE},
		{"RSA4096", key_certificate.KEYCERT_SIGN_RSA4096, key_certificate.KEYCERT_SIGN_RSA4096_SIZE},
		{"Ed25519", key_certificate.KEYCERT_SIGN_ED25519, key_certificate.KEYCERT_SIGN_ED25519_SIZE},
		{"Ed25519ph", key_certificate.KEYCERT_SIGN_ED25519PH, key_certificate.KEYCERT_SIGN_ED25519PH_SIZE},
		{"RedDSA", key_certificate.KEYCERT_SIGN_REDDSA_ED25519, key_certificate.KEYCERT_SIGN_ED25519_SIZE},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := SigningPublicKeySize(tc.sigType)
			assert.Equal(t, tc.expected, got, "size mismatch for %s (type %d)", tc.name, tc.sigType)
		})
	}

	t.Run("unknown_type_returns_zero", func(t *testing.T) {
		assert.Equal(t, 0, SigningPublicKeySize(9999))
	})
}
