// Package offline_signature implements comprehensive tests for the I2P OfflineSignature structure.
package offline_signature

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"

	"github.com/go-i2p/common/key_certificate"
	"github.com/go-i2p/common/signature"
	"github.com/stretchr/testify/assert"
)

// TestReadOfflineSignatureValidEdDSA tests parsing a valid OfflineSignature with Ed25519 keys.
func TestReadOfflineSignatureValidEdDSA(t *testing.T) {
	// Create test data for OfflineSignature with Ed25519 transient key and destination
	// Structure: expires(4) + sigtype(2) + transient_key(32) + signature(64) = 102 bytes
	expires := uint32(1735689600) // Jan 1, 2025 00:00:00 UTC
	transientSigType := uint16(key_certificate.KEYCERT_SIGN_ED25519)
	transientKeySize := key_certificate.KEYCERT_SIGN_ED25519_SIZE // 32 bytes
	destSigType := uint16(signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519)
	signatureSize := signature.EdDSA_SHA512_Ed25519_SIZE // 64 bytes

	data := make([]byte, EXPIRES_SIZE+SIGTYPE_SIZE+transientKeySize+signatureSize)
	binary.BigEndian.PutUint32(data[0:4], expires)
	binary.BigEndian.PutUint16(data[4:6], transientSigType)

	// Fill transient key with test pattern
	for i := 0; i < transientKeySize; i++ {
		data[6+i] = byte(i)
	}

	// Fill signature with test pattern
	sigOffset := 6 + transientKeySize
	for i := 0; i < signatureSize; i++ {
		data[sigOffset+i] = byte(0xFF - i)
	}

	// Add extra data to test remainder
	extraData := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	data = append(data, extraData...)

	// Parse the OfflineSignature
	offlineSig, remainder, err := ReadOfflineSignature(data, destSigType)

	// Assertions
	assert.NoError(t, err, "should parse valid Ed25519 OfflineSignature without error")
	assert.Equal(t, expires, offlineSig.Expires(), "expires timestamp should match")
	assert.Equal(t, transientSigType, offlineSig.TransientSigType(), "transient signature type should match")
	assert.Equal(t, transientKeySize, len(offlineSig.TransientPublicKey()), "transient key size should match")
	assert.Equal(t, signatureSize, len(offlineSig.Signature()), "signature size should match")
	assert.Equal(t, destSigType, offlineSig.DestinationSigType(), "destination signature type should match")
	assert.Equal(t, extraData, remainder, "remainder should contain extra data")
}

// TestReadOfflineSignatureVariousSignatureTypes tests parsing with different signature algorithms.
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

// TestReadOfflineSignatureInsufficientData tests error handling for truncated data.
func TestReadOfflineSignatureInsufficientData(t *testing.T) {
	testCases := []struct {
		name     string
		dataSize int
	}{
		{"empty_data", 0},
		{"only_expires", 4},
		{"expires_and_partial_sigtype", 5},
		{"header_only", 6},
		{"partial_transient_key", 10},
		{"missing_signature", 38}, // header + full transient key (32) but no signature
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			data := make([]byte, tc.dataSize)
			if tc.dataSize >= 6 {
				binary.BigEndian.PutUint16(data[4:6], key_certificate.KEYCERT_SIGN_ED25519)
			}

			_, _, err := ReadOfflineSignature(data, signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519)

			assert.Error(t, err, "should return error for insufficient data")
			assert.ErrorIs(t, err, ErrInsufficientData, "error should be ErrInsufficientData")
		})
	}
}

// TestReadOfflineSignatureUnknownSignatureType tests error handling for unknown signature types.
func TestReadOfflineSignatureUnknownSignatureType(t *testing.T) {
	testCases := []struct {
		name               string
		transientSigType   uint16
		destinationSigType uint16
	}{
		{"unknown_transient_type", 999, signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519},
		{"unknown_destination_type", key_certificate.KEYCERT_SIGN_ED25519, 999},
		{"both_unknown", 999, 888},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			data := make([]byte, 200) // Sufficient size
			binary.BigEndian.PutUint32(data[0:4], uint32(1735689600))
			binary.BigEndian.PutUint16(data[4:6], tc.transientSigType)

			_, _, err := ReadOfflineSignature(data, tc.destinationSigType)

			assert.Error(t, err, "should return error for unknown signature type")
			assert.ErrorIs(t, err, ErrUnknownSignatureType, "error should be ErrUnknownSignatureType")
		})
	}
}

// TestNewOfflineSignatureValid tests creating a new OfflineSignature with valid parameters.
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

// TestNewOfflineSignatureInvalidSizes tests error handling for mismatched key/signature sizes.
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
			transientKeySize:   16, // Wrong size, should be 32
			destinationSigType: signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519,
			signatureSize:      signature.EdDSA_SHA512_Ed25519_SIZE,
		},
		{
			name:               "wrong_signature_size",
			transientSigType:   key_certificate.KEYCERT_SIGN_ED25519,
			transientKeySize:   key_certificate.KEYCERT_SIGN_ED25519_SIZE,
			destinationSigType: signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519,
			signatureSize:      32, // Wrong size, should be 64
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

// TestOfflineSignatureSerialization tests round-trip serialization (Bytes() -> parse).
func TestOfflineSignatureSerialization(t *testing.T) {
	expires := uint32(1735689600)
	transientSigType := key_certificate.KEYCERT_SIGN_ED25519
	transientKey := make([]byte, key_certificate.KEYCERT_SIGN_ED25519_SIZE)
	sig := make([]byte, signature.EdDSA_SHA512_Ed25519_SIZE)
	destSigType := signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519

	// Fill with test pattern
	for i := range transientKey {
		transientKey[i] = byte(i)
	}
	for i := range sig {
		sig[i] = byte(0xFF - i)
	}

	// Create OfflineSignature
	original, err := NewOfflineSignature(expires, uint16(transientSigType), transientKey, sig, uint16(destSigType))
	assert.NoError(t, err)

	// Serialize
	serialized := original.Bytes()

	// Parse back
	parsed, remainder, err := ReadOfflineSignature(serialized, uint16(destSigType))

	// Assertions
	assert.NoError(t, err, "should parse serialized data without error")
	assert.Empty(t, remainder, "should have no remainder")
	assert.Equal(t, original.Expires(), parsed.Expires())
	assert.Equal(t, original.TransientSigType(), parsed.TransientSigType())
	assert.Equal(t, original.TransientPublicKey(), parsed.TransientPublicKey())
	assert.Equal(t, original.Signature(), parsed.Signature())
	assert.Equal(t, original.DestinationSigType(), parsed.DestinationSigType())
	assert.Equal(t, original.Len(), len(serialized))
}

// TestOfflineSignatureIsExpired tests expiration checking.
func TestOfflineSignatureIsExpired(t *testing.T) {
	transientKey := make([]byte, key_certificate.KEYCERT_SIGN_ED25519_SIZE)
	sig := make([]byte, signature.EdDSA_SHA512_Ed25519_SIZE)

	testCases := []struct {
		name     string
		expires  uint32
		expected bool
	}{
		{
			name:     "expired_signature",
			expires:  uint32(time.Now().UTC().Add(-1 * time.Hour).Unix()),
			expected: true,
		},
		{
			name:     "valid_signature",
			expires:  uint32(time.Now().UTC().Add(24 * time.Hour).Unix()),
			expected: false,
		},
		{
			name:     "future_signature",
			expires:  uint32(time.Now().UTC().Add(365 * 24 * time.Hour).Unix()),
			expected: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			offlineSig, err := NewOfflineSignature(
				tc.expires,
				key_certificate.KEYCERT_SIGN_ED25519,
				transientKey,
				sig,
				signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519,
			)
			assert.NoError(t, err)

			isExpired := offlineSig.IsExpired()
			assert.Equal(t, tc.expected, isExpired, "expiration status should match expected")
		})
	}
}

// TestOfflineSignatureExpiresTime tests time conversion.
func TestOfflineSignatureExpiresTime(t *testing.T) {
	expectedTime := time.Date(2025, time.January, 1, 0, 0, 0, 0, time.UTC)
	expires := uint32(expectedTime.Unix())

	transientKey := make([]byte, key_certificate.KEYCERT_SIGN_ED25519_SIZE)
	sig := make([]byte, signature.EdDSA_SHA512_Ed25519_SIZE)

	offlineSig, err := NewOfflineSignature(
		expires,
		key_certificate.KEYCERT_SIGN_ED25519,
		transientKey,
		sig,
		signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519,
	)
	assert.NoError(t, err)

	expiresTime := offlineSig.ExpiresTime()
	assert.Equal(t, expectedTime.Unix(), expiresTime.Unix(), "time conversion should match")
}

// TestOfflineSignatureString tests string representation.
func TestOfflineSignatureString(t *testing.T) {
	expires := uint32(1735689600)
	transientKey := make([]byte, key_certificate.KEYCERT_SIGN_ED25519_SIZE)
	sig := make([]byte, signature.EdDSA_SHA512_Ed25519_SIZE)

	offlineSig, err := NewOfflineSignature(
		expires,
		key_certificate.KEYCERT_SIGN_ED25519,
		transientKey,
		sig,
		signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519,
	)
	assert.NoError(t, err)

	str := offlineSig.String()
	assert.Contains(t, str, "OfflineSignature{")
	assert.Contains(t, str, "expires:")
	assert.Contains(t, str, "transient_sigtype:")
	assert.Contains(t, str, "signature_len:")
}

// TestOfflineSignatureAccessorsCopy tests that accessors return copies, not references.
func TestOfflineSignatureAccessorsCopy(t *testing.T) {
	transientKey := make([]byte, key_certificate.KEYCERT_SIGN_ED25519_SIZE)
	sig := make([]byte, signature.EdDSA_SHA512_Ed25519_SIZE)

	// Fill with test pattern
	for i := range transientKey {
		transientKey[i] = byte(i)
	}
	for i := range sig {
		sig[i] = byte(0xFF - i)
	}

	offlineSig, err := NewOfflineSignature(
		uint32(1735689600),
		key_certificate.KEYCERT_SIGN_ED25519,
		transientKey,
		sig,
		signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519,
	)
	assert.NoError(t, err)

	// Get copies
	keyCopy := offlineSig.TransientPublicKey()
	sigCopy := offlineSig.Signature()

	// Modify copies
	keyCopy[0] = 0xFF
	sigCopy[0] = 0x00

	// Original should be unchanged
	assert.Equal(t, byte(0), offlineSig.TransientPublicKey()[0], "transient key should not be modified")
	assert.Equal(t, byte(0xFF), offlineSig.Signature()[0], "signature should not be modified")
}

// TestOfflineSignatureLenConsistency tests that Len() matches Bytes() length.
func TestOfflineSignatureLenConsistency(t *testing.T) {
	transientKey := make([]byte, key_certificate.KEYCERT_SIGN_ED25519_SIZE)
	sig := make([]byte, signature.EdDSA_SHA512_Ed25519_SIZE)

	offlineSig, err := NewOfflineSignature(
		uint32(1735689600),
		key_certificate.KEYCERT_SIGN_ED25519,
		transientKey,
		sig,
		signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519,
	)
	assert.NoError(t, err)

	assert.Equal(t, offlineSig.Len(), len(offlineSig.Bytes()), "Len() should match Bytes() length")
}

// TestOfflineSignatureExpiresDate tests I2P Date conversion.
func TestOfflineSignatureExpiresDate(t *testing.T) {
	expires := uint32(1735689600) // Seconds since epoch
	transientKey := make([]byte, key_certificate.KEYCERT_SIGN_ED25519_SIZE)
	sig := make([]byte, signature.EdDSA_SHA512_Ed25519_SIZE)

	offlineSig, err := NewOfflineSignature(
		expires,
		uint16(key_certificate.KEYCERT_SIGN_ED25519),
		transientKey,
		sig,
		uint16(signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519),
	)
	assert.NoError(t, err)

	i2pDate, err := offlineSig.ExpiresDate()
	assert.NoError(t, err, "should convert to I2P Date without error")

	expectedMilliseconds := uint64(expires) * 1000

	// Convert I2PDate back to milliseconds for comparison
	i2pBytes := i2pDate.Bytes()
	actualMilliseconds := binary.BigEndian.Uint64(i2pBytes)

	assert.Equal(t, expectedMilliseconds, actualMilliseconds, "I2P Date conversion should match")
}

// BenchmarkReadOfflineSignature benchmarks parsing performance.
func BenchmarkReadOfflineSignature(b *testing.B) {
	data := make([]byte, 102) // Ed25519 OfflineSignature size
	binary.BigEndian.PutUint32(data[0:4], uint32(1735689600))
	binary.BigEndian.PutUint16(data[4:6], key_certificate.KEYCERT_SIGN_ED25519)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = ReadOfflineSignature(data, signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519)
	}
}

// BenchmarkOfflineSignatureBytes benchmarks serialization performance.
func BenchmarkOfflineSignatureBytes(b *testing.B) {
	transientKey := make([]byte, key_certificate.KEYCERT_SIGN_ED25519_SIZE)
	sig := make([]byte, signature.EdDSA_SHA512_Ed25519_SIZE)

	offlineSig, _ := NewOfflineSignature(
		uint32(1735689600),
		key_certificate.KEYCERT_SIGN_ED25519,
		transientKey,
		sig,
		signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519,
	)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = offlineSig.Bytes()
	}
}

// TestOfflineSignatureMinimumSize tests the minimum size constant.
func TestOfflineSignatureMinimumSize(t *testing.T) {
	// Ed25519 gives us the minimum: 4 + 2 + 32 + 64 = 102
	assert.Equal(t, 102, OFFLINE_SIGNATURE_MIN_SIZE, "minimum size constant should be 102")

	// Verify actual minimum
	transientKey := make([]byte, key_certificate.KEYCERT_SIGN_ED25519_SIZE)
	sig := make([]byte, signature.EdDSA_SHA512_Ed25519_SIZE)

	offlineSig, err := NewOfflineSignature(
		uint32(1735689600),
		key_certificate.KEYCERT_SIGN_ED25519,
		transientKey,
		sig,
		signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519,
	)
	assert.NoError(t, err)

	assert.GreaterOrEqual(t, offlineSig.Len(), OFFLINE_SIGNATURE_MIN_SIZE,
		"actual OfflineSignature should be at least minimum size")
}

// TestOfflineSignatureBytesIdentical tests that serialization is deterministic.
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
		transientKey,
		sig,
		signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519,
	)
	assert.NoError(t, err)

	// Serialize multiple times
	bytes1 := offlineSig.Bytes()
	bytes2 := offlineSig.Bytes()
	bytes3 := offlineSig.Bytes()

	// All should be identical
	assert.True(t, bytes.Equal(bytes1, bytes2), "first and second serialization should be identical")
	assert.True(t, bytes.Equal(bytes2, bytes3), "second and third serialization should be identical")
}
