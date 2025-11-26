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

// TestOfflineSignatureValidate tests the Validate() method with valid signatures.
func TestOfflineSignatureValidate(t *testing.T) {
	// Create a valid offline signature with future expiration
	futureExpires := uint32(time.Now().UTC().Add(24 * time.Hour).Unix())
	transientKey := make([]byte, key_certificate.KEYCERT_SIGN_ED25519_SIZE)
	sig := make([]byte, signature.EdDSA_SHA512_Ed25519_SIZE)

	offlineSig, err := NewOfflineSignature(
		futureExpires,
		key_certificate.KEYCERT_SIGN_ED25519,
		transientKey,
		sig,
		signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519,
	)
	assert.NoError(t, err)

	// Validate should pass
	err = offlineSig.Validate()
	assert.NoError(t, err, "valid offline signature should pass validation")
}

// TestOfflineSignatureValidateExpired tests Validate() with expired signatures.
func TestOfflineSignatureValidateExpired(t *testing.T) {
	// Create an expired offline signature
	pastExpires := uint32(time.Now().UTC().Add(-1 * time.Hour).Unix())
	transientKey := make([]byte, key_certificate.KEYCERT_SIGN_ED25519_SIZE)
	sig := make([]byte, signature.EdDSA_SHA512_Ed25519_SIZE)

	offlineSig, err := NewOfflineSignature(
		pastExpires,
		key_certificate.KEYCERT_SIGN_ED25519,
		transientKey,
		sig,
		signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519,
	)
	assert.NoError(t, err)

	// Validate should fail due to expiration
	err = offlineSig.Validate()
	assert.Error(t, err, "expired offline signature should fail validation")
	assert.ErrorIs(t, err, ErrExpiredOfflineSignature, "error should be ErrExpiredOfflineSignature")
	assert.Contains(t, err.Error(), "expired at", "error message should contain expiration time")
}

// TestOfflineSignatureValidateZeroExpiration tests Validate() with zero expiration.
func TestOfflineSignatureValidateZeroExpiration(t *testing.T) {
	transientKey := make([]byte, key_certificate.KEYCERT_SIGN_ED25519_SIZE)
	sig := make([]byte, signature.EdDSA_SHA512_Ed25519_SIZE)

	offlineSig, err := NewOfflineSignature(
		0, // Zero expiration
		key_certificate.KEYCERT_SIGN_ED25519,
		transientKey,
		sig,
		signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519,
	)
	assert.NoError(t, err)

	// Validate should fail due to zero expiration
	err = offlineSig.Validate()
	assert.Error(t, err, "offline signature with zero expiration should fail validation")
	assert.Contains(t, err.Error(), "zero expiration", "error message should mention zero expiration")
}

// TestOfflineSignatureValidateNil tests Validate() with nil signature.
func TestOfflineSignatureValidateNil(t *testing.T) {
	var offlineSig *OfflineSignature = nil

	err := offlineSig.Validate()
	assert.Error(t, err, "nil offline signature should fail validation")
	assert.Contains(t, err.Error(), "nil", "error message should mention nil")
}

// TestOfflineSignatureValidateInvalidTransientKeyType tests Validate() with unknown transient key type.
func TestOfflineSignatureValidateInvalidTransientKeyType(t *testing.T) {
	futureExpires := uint32(time.Now().UTC().Add(24 * time.Hour).Unix())
	transientKey := make([]byte, 32) // Valid size
	sig := make([]byte, signature.EdDSA_SHA512_Ed25519_SIZE)

	// Create signature with invalid transient key type (999 is unknown)
	offlineSig := OfflineSignature{
		expires:            futureExpires,
		sigtype:            999, // Invalid type
		transientPublicKey: transientKey,
		signature:          sig,
		destinationSigType: signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519,
	}

	// Validate should fail due to unknown signature type
	err := offlineSig.Validate()
	assert.Error(t, err, "offline signature with unknown transient key type should fail validation")
	assert.ErrorIs(t, err, ErrUnknownSignatureType, "error should be ErrUnknownSignatureType")
	assert.Contains(t, err.Error(), "transient key type", "error message should mention transient key type")
}

// TestOfflineSignatureValidateInvalidDestinationSigType tests Validate() with unknown destination type.
func TestOfflineSignatureValidateInvalidDestinationSigType(t *testing.T) {
	futureExpires := uint32(time.Now().UTC().Add(24 * time.Hour).Unix())
	transientKey := make([]byte, key_certificate.KEYCERT_SIGN_ED25519_SIZE)
	sig := make([]byte, 64) // Valid size

	// Create signature with invalid destination signature type (888 is unknown)
	offlineSig := OfflineSignature{
		expires:            futureExpires,
		sigtype:            key_certificate.KEYCERT_SIGN_ED25519,
		transientPublicKey: transientKey,
		signature:          sig,
		destinationSigType: 888, // Invalid type
	}

	// Validate should fail due to unknown destination signature type
	err := offlineSig.Validate()
	assert.Error(t, err, "offline signature with unknown destination type should fail validation")
	assert.ErrorIs(t, err, ErrUnknownSignatureType, "error should be ErrUnknownSignatureType")
	assert.Contains(t, err.Error(), "destination signature type", "error message should mention destination signature type")
}

// TestOfflineSignatureValidateWrongTransientKeySize tests Validate() with mismatched key size.
func TestOfflineSignatureValidateWrongTransientKeySize(t *testing.T) {
	futureExpires := uint32(time.Now().UTC().Add(24 * time.Hour).Unix())
	transientKey := make([]byte, 16) // Wrong size, should be 32 for Ed25519
	sig := make([]byte, signature.EdDSA_SHA512_Ed25519_SIZE)

	// Create signature with mismatched transient key size
	offlineSig := OfflineSignature{
		expires:            futureExpires,
		sigtype:            key_certificate.KEYCERT_SIGN_ED25519,
		transientPublicKey: transientKey,
		signature:          sig,
		destinationSigType: signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519,
	}

	// Validate should fail due to size mismatch
	err := offlineSig.Validate()
	assert.Error(t, err, "offline signature with wrong transient key size should fail validation")
	assert.Contains(t, err.Error(), "transient public key size mismatch", "error message should mention size mismatch")
	assert.Contains(t, err.Error(), "expected 32", "error message should mention expected size")
	assert.Contains(t, err.Error(), "got 16", "error message should mention actual size")
}

// TestOfflineSignatureValidateWrongSignatureSize tests Validate() with mismatched signature size.
func TestOfflineSignatureValidateWrongSignatureSize(t *testing.T) {
	futureExpires := uint32(time.Now().UTC().Add(24 * time.Hour).Unix())
	transientKey := make([]byte, key_certificate.KEYCERT_SIGN_ED25519_SIZE)
	sig := make([]byte, 32) // Wrong size, should be 64 for Ed25519

	// Create signature with mismatched signature size
	offlineSig := OfflineSignature{
		expires:            futureExpires,
		sigtype:            key_certificate.KEYCERT_SIGN_ED25519,
		transientPublicKey: transientKey,
		signature:          sig,
		destinationSigType: signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519,
	}

	// Validate should fail due to signature size mismatch
	err := offlineSig.Validate()
	assert.Error(t, err, "offline signature with wrong signature size should fail validation")
	assert.Contains(t, err.Error(), "signature size mismatch", "error message should mention size mismatch")
	assert.Contains(t, err.Error(), "expected 64", "error message should mention expected size")
	assert.Contains(t, err.Error(), "got 32", "error message should mention actual size")
}

// TestOfflineSignatureIsValid tests the IsValid() convenience method.
func TestOfflineSignatureIsValid(t *testing.T) {
	testCases := []struct {
		name     string
		setup    func() OfflineSignature
		expected bool
	}{
		{
			name: "valid_signature",
			setup: func() OfflineSignature {
				futureExpires := uint32(time.Now().UTC().Add(24 * time.Hour).Unix())
				transientKey := make([]byte, key_certificate.KEYCERT_SIGN_ED25519_SIZE)
				sig := make([]byte, signature.EdDSA_SHA512_Ed25519_SIZE)
				offlineSig, _ := NewOfflineSignature(
					futureExpires,
					key_certificate.KEYCERT_SIGN_ED25519,
					transientKey,
					sig,
					signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519,
				)
				return offlineSig
			},
			expected: true,
		},
		{
			name: "expired_signature",
			setup: func() OfflineSignature {
				pastExpires := uint32(time.Now().UTC().Add(-1 * time.Hour).Unix())
				transientKey := make([]byte, key_certificate.KEYCERT_SIGN_ED25519_SIZE)
				sig := make([]byte, signature.EdDSA_SHA512_Ed25519_SIZE)
				offlineSig, _ := NewOfflineSignature(
					pastExpires,
					key_certificate.KEYCERT_SIGN_ED25519,
					transientKey,
					sig,
					signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519,
				)
				return offlineSig
			},
			expected: false,
		},
		{
			name: "zero_expiration",
			setup: func() OfflineSignature {
				transientKey := make([]byte, key_certificate.KEYCERT_SIGN_ED25519_SIZE)
				sig := make([]byte, signature.EdDSA_SHA512_Ed25519_SIZE)
				offlineSig, _ := NewOfflineSignature(
					0,
					key_certificate.KEYCERT_SIGN_ED25519,
					transientKey,
					sig,
					signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519,
				)
				return offlineSig
			},
			expected: false,
		},
		{
			name: "invalid_transient_key_size",
			setup: func() OfflineSignature {
				futureExpires := uint32(time.Now().UTC().Add(24 * time.Hour).Unix())
				transientKey := make([]byte, 16) // Wrong size
				sig := make([]byte, signature.EdDSA_SHA512_Ed25519_SIZE)
				return OfflineSignature{
					expires:            futureExpires,
					sigtype:            key_certificate.KEYCERT_SIGN_ED25519,
					transientPublicKey: transientKey,
					signature:          sig,
					destinationSigType: signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519,
				}
			},
			expected: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			offlineSig := tc.setup()
			isValid := offlineSig.IsValid()
			assert.Equal(t, tc.expected, isValid, "IsValid() result should match expected")
		})
	}
}

// TestOfflineSignatureIsValidNil tests IsValid() with nil signature.
func TestOfflineSignatureIsValidNil(t *testing.T) {
	var offlineSig *OfflineSignature = nil
	assert.False(t, offlineSig.IsValid(), "nil offline signature should not be valid")
}

// TestOfflineSignatureValidateRoundTrip tests validation after round-trip serialization.
func TestOfflineSignatureValidateRoundTrip(t *testing.T) {
	// Create a valid offline signature
	futureExpires := uint32(time.Now().UTC().Add(24 * time.Hour).Unix())
	transientKey := make([]byte, key_certificate.KEYCERT_SIGN_ED25519_SIZE)
	sig := make([]byte, signature.EdDSA_SHA512_Ed25519_SIZE)

	for i := range transientKey {
		transientKey[i] = byte(i)
	}
	for i := range sig {
		sig[i] = byte(0xFF - i)
	}

	original, err := NewOfflineSignature(
		futureExpires,
		key_certificate.KEYCERT_SIGN_ED25519,
		transientKey,
		sig,
		signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519,
	)
	assert.NoError(t, err)
	assert.NoError(t, original.Validate(), "original should be valid")
	assert.True(t, original.IsValid(), "original should pass IsValid()")

	// Serialize and parse back
	serialized := original.Bytes()
	parsed, remainder, err := ReadOfflineSignature(serialized, signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519)
	assert.NoError(t, err)
	assert.Empty(t, remainder)

	// Parsed signature should also be valid
	assert.NoError(t, parsed.Validate(), "parsed signature should be valid")
	assert.True(t, parsed.IsValid(), "parsed signature should pass IsValid()")
}

// TestOfflineSignatureValidateVariousSignatureTypes tests validation with different crypto algorithms.
func TestOfflineSignatureValidateVariousSignatureTypes(t *testing.T) {
	testCases := []struct {
		name               string
		transientSigType   uint16
		destinationSigType uint16
		transientKeySize   int
		signatureSize      int
	}{
		{
			name:               "DSA_SHA1",
			transientSigType:   key_certificate.KEYCERT_SIGN_DSA_SHA1,
			destinationSigType: signature.SIGNATURE_TYPE_DSA_SHA1,
			transientKeySize:   key_certificate.KEYCERT_SIGN_DSA_SHA1_SIZE,
			signatureSize:      signature.DSA_SHA1_SIZE,
		},
		{
			name:               "P256",
			transientSigType:   key_certificate.KEYCERT_SIGN_P256,
			destinationSigType: signature.SIGNATURE_TYPE_ECDSA_SHA256_P256,
			transientKeySize:   key_certificate.KEYCERT_SIGN_P256_SIZE,
			signatureSize:      signature.ECDSA_SHA256_P256_SIZE,
		},
		{
			name:               "RSA4096",
			transientSigType:   key_certificate.KEYCERT_SIGN_RSA4096,
			destinationSigType: signature.SIGNATURE_TYPE_RSA_SHA512_4096,
			transientKeySize:   key_certificate.KEYCERT_SIGN_RSA4096_SIZE,
			signatureSize:      signature.RSA_SHA512_4096_SIZE,
		},
		{
			name:               "RedDSA",
			transientSigType:   key_certificate.KEYCERT_SIGN_REDDSA_ED25519,
			destinationSigType: signature.SIGNATURE_TYPE_REDDSA_SHA512_ED25519,
			transientKeySize:   key_certificate.KEYCERT_SIGN_ED25519_SIZE,
			signatureSize:      signature.RedDSA_SHA512_Ed25519_SIZE,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			futureExpires := uint32(time.Now().UTC().Add(24 * time.Hour).Unix())
			transientKey := make([]byte, tc.transientKeySize)
			sig := make([]byte, tc.signatureSize)

			offlineSig, err := NewOfflineSignature(
				futureExpires,
				tc.transientSigType,
				transientKey,
				sig,
				tc.destinationSigType,
			)
			assert.NoError(t, err)

			// Validate should pass for all valid signature types
			assert.NoError(t, offlineSig.Validate(), "validation should pass for valid signature type")
			assert.True(t, offlineSig.IsValid(), "IsValid() should return true for valid signature type")
		})
	}
}
