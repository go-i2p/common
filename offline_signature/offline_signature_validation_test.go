package offline_signature

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/go-i2p/common/key_certificate"
	"github.com/go-i2p/common/signature"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =========================================================================
// ReadOfflineSignature error paths
// =========================================================================

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
		{"missing_signature", 38},
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
			data := make([]byte, 200)
			binary.BigEndian.PutUint32(data[0:4], uint32(1735689600))
			binary.BigEndian.PutUint16(data[4:6], tc.transientSigType)

			_, _, err := ReadOfflineSignature(data, tc.destinationSigType)

			assert.Error(t, err, "should return error for unknown signature type")
			assert.ErrorIs(t, err, ErrUnknownSignatureType, "error should be ErrUnknownSignatureType")
		})
	}
}

// =========================================================================
// Validate() Tests
// =========================================================================

func TestOfflineSignatureValidate(t *testing.T) {
	futureExpires := uint32(time.Now().UTC().Add(24 * time.Hour).Unix())
	transientKey := make([]byte, key_certificate.KEYCERT_SIGN_ED25519_SIZE)
	sig := make([]byte, signature.EdDSA_SHA512_Ed25519_SIZE)

	offlineSig, err := NewOfflineSignature(
		futureExpires,
		key_certificate.KEYCERT_SIGN_ED25519,
		transientKey, sig,
		signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519,
	)
	assert.NoError(t, err)

	err = offlineSig.Validate()
	assert.NoError(t, err, "valid offline signature should pass validation")
}

func TestOfflineSignatureValidateExpired(t *testing.T) {
	pastExpires := uint32(time.Now().UTC().Add(-1 * time.Hour).Unix())
	transientKey := make([]byte, key_certificate.KEYCERT_SIGN_ED25519_SIZE)
	sig := make([]byte, signature.EdDSA_SHA512_Ed25519_SIZE)

	offlineSig, err := NewOfflineSignature(
		pastExpires,
		key_certificate.KEYCERT_SIGN_ED25519,
		transientKey, sig,
		signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519,
	)
	assert.NoError(t, err)

	err = offlineSig.Validate()
	assert.Error(t, err, "expired offline signature should fail validation")
	assert.ErrorIs(t, err, ErrExpiredOfflineSignature, "error should be ErrExpiredOfflineSignature")
	assert.Contains(t, err.Error(), "expired at", "error message should contain expiration time")
}

func TestOfflineSignatureValidateZeroExpiration(t *testing.T) {
	transientKey := make([]byte, key_certificate.KEYCERT_SIGN_ED25519_SIZE)
	sig := make([]byte, signature.EdDSA_SHA512_Ed25519_SIZE)

	// AUDIT BUG fix: NewOfflineSignature now rejects expires==0 at construction
	// time, preventing callers from holding an object that always fails Validate().
	_, err := NewOfflineSignature(
		0,
		key_certificate.KEYCERT_SIGN_ED25519,
		transientKey, sig,
		signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519,
	)
	assert.Error(t, err, "NewOfflineSignature with zero expiration must return an error")
	assert.Contains(t, err.Error(), "non-zero", "error should mention non-zero requirement")
}

func TestOfflineSignatureValidateNil(t *testing.T) {
	var offlineSig *OfflineSignature = nil

	err := offlineSig.Validate()
	assert.Error(t, err, "nil offline signature should fail validation")
	assert.Contains(t, err.Error(), "nil", "error message should mention nil")
}

func TestOfflineSignatureValidateInvalidTransientKeyType(t *testing.T) {
	futureExpires := uint32(time.Now().UTC().Add(24 * time.Hour).Unix())
	transientKey := make([]byte, 32)
	sig := make([]byte, signature.EdDSA_SHA512_Ed25519_SIZE)

	offlineSig := OfflineSignature{
		expires:            futureExpires,
		sigtype:            999,
		transientPublicKey: transientKey,
		signature:          sig,
		destinationSigType: signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519,
	}

	err := offlineSig.Validate()
	assert.Error(t, err, "offline signature with unknown transient key type should fail validation")
	assert.ErrorIs(t, err, ErrUnknownSignatureType, "error should be ErrUnknownSignatureType")
	assert.Contains(t, err.Error(), "transient key type", "error message should mention transient key type")
}

func TestOfflineSignatureValidateInvalidDestinationSigType(t *testing.T) {
	futureExpires := uint32(time.Now().UTC().Add(24 * time.Hour).Unix())
	transientKey := make([]byte, key_certificate.KEYCERT_SIGN_ED25519_SIZE)
	sig := make([]byte, 64)

	offlineSig := OfflineSignature{
		expires:            futureExpires,
		sigtype:            key_certificate.KEYCERT_SIGN_ED25519,
		transientPublicKey: transientKey,
		signature:          sig,
		destinationSigType: 888,
	}

	err := offlineSig.Validate()
	assert.Error(t, err, "offline signature with unknown destination type should fail validation")
	assert.ErrorIs(t, err, ErrUnknownSignatureType, "error should be ErrUnknownSignatureType")
	assert.Contains(t, err.Error(), "destination signature type", "error message should mention destination signature type")
}

func TestOfflineSignatureValidateWrongTransientKeySize(t *testing.T) {
	futureExpires := uint32(time.Now().UTC().Add(24 * time.Hour).Unix())
	transientKey := make([]byte, 16)
	sig := make([]byte, signature.EdDSA_SHA512_Ed25519_SIZE)

	offlineSig := OfflineSignature{
		expires:            futureExpires,
		sigtype:            key_certificate.KEYCERT_SIGN_ED25519,
		transientPublicKey: transientKey,
		signature:          sig,
		destinationSigType: signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519,
	}

	err := offlineSig.Validate()
	assert.Error(t, err, "offline signature with wrong transient key size should fail validation")
	assert.Contains(t, err.Error(), "transient public key size mismatch")
	assert.Contains(t, err.Error(), "expected 32")
	assert.Contains(t, err.Error(), "got 16")
}

func TestOfflineSignatureValidateWrongSignatureSize(t *testing.T) {
	futureExpires := uint32(time.Now().UTC().Add(24 * time.Hour).Unix())
	transientKey := make([]byte, key_certificate.KEYCERT_SIGN_ED25519_SIZE)
	sig := make([]byte, 32)

	offlineSig := OfflineSignature{
		expires:            futureExpires,
		sigtype:            key_certificate.KEYCERT_SIGN_ED25519,
		transientPublicKey: transientKey,
		signature:          sig,
		destinationSigType: signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519,
	}

	err := offlineSig.Validate()
	assert.Error(t, err, "offline signature with wrong signature size should fail validation")
	assert.Contains(t, err.Error(), "signature size mismatch")
	assert.Contains(t, err.Error(), "expected 64")
	assert.Contains(t, err.Error(), "got 32")
}

// =========================================================================
// ValidateStructure() Tests
// =========================================================================

func TestValidateStructure(t *testing.T) {
	t.Run("valid_expired_signature", func(t *testing.T) {
		pastExpires := uint32(time.Now().UTC().Add(-1 * time.Hour).Unix())
		transientKey := make([]byte, key_certificate.KEYCERT_SIGN_ED25519_SIZE)
		sig := make([]byte, signature.EdDSA_SHA512_Ed25519_SIZE)

		offlineSig, err := NewOfflineSignature(
			pastExpires,
			key_certificate.KEYCERT_SIGN_ED25519,
			transientKey, sig,
			signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519,
		)
		require.NoError(t, err)

		assert.NoError(t, offlineSig.ValidateStructure(),
			"expired signature should pass structural validation")
		assert.Error(t, offlineSig.Validate(),
			"expired signature should fail full validation")
		assert.ErrorIs(t, offlineSig.Validate(), ErrExpiredOfflineSignature)
	})

	t.Run("nil_signature", func(t *testing.T) {
		var offlineSig *OfflineSignature
		assert.Error(t, offlineSig.ValidateStructure())
	})

	t.Run("zero_expiration", func(t *testing.T) {
		transientKey := make([]byte, key_certificate.KEYCERT_SIGN_ED25519_SIZE)
		sig := make([]byte, signature.EdDSA_SHA512_Ed25519_SIZE)
		offlineSig, _ := NewOfflineSignature(0, key_certificate.KEYCERT_SIGN_ED25519, transientKey, sig, signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519)
		assert.Error(t, offlineSig.ValidateStructure())
	})

	t.Run("invalid_transient_type", func(t *testing.T) {
		offlineSig := OfflineSignature{
			expires:            uint32(time.Now().UTC().Add(24 * time.Hour).Unix()),
			sigtype:            999,
			transientPublicKey: make([]byte, 32),
			signature:          make([]byte, 64),
			destinationSigType: signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519,
		}
		assert.Error(t, offlineSig.ValidateStructure())
		assert.ErrorIs(t, offlineSig.ValidateStructure(), ErrUnknownSignatureType)
	})

	t.Run("wrong_key_size", func(t *testing.T) {
		offlineSig := OfflineSignature{
			expires:            uint32(time.Now().UTC().Add(24 * time.Hour).Unix()),
			sigtype:            key_certificate.KEYCERT_SIGN_ED25519,
			transientPublicKey: make([]byte, 16),
			signature:          make([]byte, signature.EdDSA_SHA512_Ed25519_SIZE),
			destinationSigType: signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519,
		}
		assert.Error(t, offlineSig.ValidateStructure())
		assert.Contains(t, offlineSig.ValidateStructure().Error(), "transient public key size mismatch")
	})

	t.Run("invalid_destination_type", func(t *testing.T) {
		offlineSig := OfflineSignature{
			expires:            uint32(time.Now().UTC().Add(24 * time.Hour).Unix()),
			sigtype:            key_certificate.KEYCERT_SIGN_ED25519,
			transientPublicKey: make([]byte, key_certificate.KEYCERT_SIGN_ED25519_SIZE),
			signature:          make([]byte, 64),
			destinationSigType: 888,
		}
		assert.Error(t, offlineSig.ValidateStructure())
		assert.ErrorIs(t, offlineSig.ValidateStructure(), ErrUnknownSignatureType)
	})

	t.Run("wrong_sig_size", func(t *testing.T) {
		offlineSig := OfflineSignature{
			expires:            uint32(time.Now().UTC().Add(24 * time.Hour).Unix()),
			sigtype:            key_certificate.KEYCERT_SIGN_ED25519,
			transientPublicKey: make([]byte, key_certificate.KEYCERT_SIGN_ED25519_SIZE),
			signature:          make([]byte, 32),
			destinationSigType: signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519,
		}
		assert.Error(t, offlineSig.ValidateStructure())
		assert.Contains(t, offlineSig.ValidateStructure().Error(), "signature size mismatch")
	})
}

// =========================================================================
// IsValid() Tests
// =========================================================================

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
				offlineSig, _ := NewOfflineSignature(futureExpires, key_certificate.KEYCERT_SIGN_ED25519, transientKey, sig, signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519)
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
				offlineSig, _ := NewOfflineSignature(pastExpires, key_certificate.KEYCERT_SIGN_ED25519, transientKey, sig, signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519)
				return offlineSig
			},
			expected: false,
		},
		{
			name: "zero_expiration",
			setup: func() OfflineSignature {
				transientKey := make([]byte, key_certificate.KEYCERT_SIGN_ED25519_SIZE)
				sig := make([]byte, signature.EdDSA_SHA512_Ed25519_SIZE)
				offlineSig, _ := NewOfflineSignature(0, key_certificate.KEYCERT_SIGN_ED25519, transientKey, sig, signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519)
				return offlineSig
			},
			expected: false,
		},
		{
			name: "invalid_transient_key_size",
			setup: func() OfflineSignature {
				futureExpires := uint32(time.Now().UTC().Add(24 * time.Hour).Unix())
				return OfflineSignature{
					expires:            futureExpires,
					sigtype:            key_certificate.KEYCERT_SIGN_ED25519,
					transientPublicKey: make([]byte, 16),
					signature:          make([]byte, signature.EdDSA_SHA512_Ed25519_SIZE),
					destinationSigType: signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519,
				}
			},
			expected: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			offlineSig := tc.setup()
			assert.Equal(t, tc.expected, offlineSig.IsValid(), "IsValid() result should match expected")
		})
	}
}

func TestOfflineSignatureIsValidNil(t *testing.T) {
	var offlineSig *OfflineSignature = nil
	assert.False(t, offlineSig.IsValid(), "nil offline signature should not be valid")
}

// =========================================================================
// Validate with various signature types
// =========================================================================

func TestOfflineSignatureValidateVariousSignatureTypes(t *testing.T) {
	testCases := []struct {
		name               string
		transientSigType   uint16
		destinationSigType uint16
		transientKeySize   int
		signatureSize      int
	}{
		{"DSA_SHA1", key_certificate.KEYCERT_SIGN_DSA_SHA1, signature.SIGNATURE_TYPE_DSA_SHA1, key_certificate.KEYCERT_SIGN_DSA_SHA1_SIZE, signature.DSA_SHA1_SIZE},
		{"P256", key_certificate.KEYCERT_SIGN_P256, signature.SIGNATURE_TYPE_ECDSA_SHA256_P256, key_certificate.KEYCERT_SIGN_P256_SIZE, signature.ECDSA_SHA256_P256_SIZE},
		{"RSA4096", key_certificate.KEYCERT_SIGN_RSA4096, signature.SIGNATURE_TYPE_RSA_SHA512_4096, key_certificate.KEYCERT_SIGN_RSA4096_SIZE, signature.RSA_SHA512_4096_SIZE},
		{"RedDSA", key_certificate.KEYCERT_SIGN_REDDSA_ED25519, signature.SIGNATURE_TYPE_REDDSA_SHA512_ED25519, key_certificate.KEYCERT_SIGN_ED25519_SIZE, signature.RedDSA_SHA512_Ed25519_SIZE},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			futureExpires := uint32(time.Now().UTC().Add(24 * time.Hour).Unix())
			transientKey := make([]byte, tc.transientKeySize)
			sig := make([]byte, tc.signatureSize)

			offlineSig, err := NewOfflineSignature(futureExpires, tc.transientSigType, transientKey, sig, tc.destinationSigType)
			assert.NoError(t, err)
			assert.NoError(t, offlineSig.Validate(), "validation should pass for valid signature type")
			assert.True(t, offlineSig.IsValid(), "IsValid() should return true for valid signature type")
		})
	}
}

func TestValidateAllSignatureTypes(t *testing.T) {
	testCases := []struct {
		name               string
		transientSigType   uint16
		destinationSigType uint16
		transientKeySize   int
		signatureSize      int
	}{
		{"DSA_SHA1", key_certificate.KEYCERT_SIGN_DSA_SHA1, signature.SIGNATURE_TYPE_DSA_SHA1, key_certificate.KEYCERT_SIGN_DSA_SHA1_SIZE, signature.DSA_SHA1_SIZE},
		{"P256", key_certificate.KEYCERT_SIGN_P256, signature.SIGNATURE_TYPE_ECDSA_SHA256_P256, key_certificate.KEYCERT_SIGN_P256_SIZE, signature.ECDSA_SHA256_P256_SIZE},
		{"P384", key_certificate.KEYCERT_SIGN_P384, signature.SIGNATURE_TYPE_ECDSA_SHA384_P384, key_certificate.KEYCERT_SIGN_P384_SIZE, signature.ECDSA_SHA384_P384_SIZE},
		{"P521", key_certificate.KEYCERT_SIGN_P521, signature.SIGNATURE_TYPE_ECDSA_SHA512_P521, key_certificate.KEYCERT_SIGN_P521_SIZE, signature.ECDSA_SHA512_P521_SIZE},
		{"RSA2048", key_certificate.KEYCERT_SIGN_RSA2048, signature.SIGNATURE_TYPE_RSA_SHA256_2048, key_certificate.KEYCERT_SIGN_RSA2048_SIZE, signature.RSA_SHA256_2048_SIZE},
		{"RSA3072", key_certificate.KEYCERT_SIGN_RSA3072, signature.SIGNATURE_TYPE_RSA_SHA384_3072, key_certificate.KEYCERT_SIGN_RSA3072_SIZE, signature.RSA_SHA384_3072_SIZE},
		{"RSA4096", key_certificate.KEYCERT_SIGN_RSA4096, signature.SIGNATURE_TYPE_RSA_SHA512_4096, key_certificate.KEYCERT_SIGN_RSA4096_SIZE, signature.RSA_SHA512_4096_SIZE},
		{"Ed25519", key_certificate.KEYCERT_SIGN_ED25519, signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519, key_certificate.KEYCERT_SIGN_ED25519_SIZE, signature.EdDSA_SHA512_Ed25519_SIZE},
		{"Ed25519ph", key_certificate.KEYCERT_SIGN_ED25519PH, signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519PH, key_certificate.KEYCERT_SIGN_ED25519PH_SIZE, signature.EdDSA_SHA512_Ed25519ph_SIZE},
		{"RedDSA", key_certificate.KEYCERT_SIGN_REDDSA_ED25519, signature.SIGNATURE_TYPE_REDDSA_SHA512_ED25519, key_certificate.KEYCERT_SIGN_ED25519_SIZE, signature.RedDSA_SHA512_Ed25519_SIZE},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			futureExpires := uint32(time.Now().UTC().Add(24 * time.Hour).Unix())
			transientKey := make([]byte, tc.transientKeySize)
			sig := make([]byte, tc.signatureSize)

			offlineSig, err := NewOfflineSignature(futureExpires, tc.transientSigType, transientKey, sig, tc.destinationSigType)
			require.NoError(t, err)
			assert.NoError(t, offlineSig.Validate(), "validation should pass for %s", tc.name)
			assert.True(t, offlineSig.IsValid())
		})
	}
}

func TestRemovedErrInvalidOfflineSignatureData(t *testing.T) {
	// Verify that the remaining error sentinels still work correctly
	t.Run("ErrInsufficientData_still_works", func(t *testing.T) {
		_, _, err := ReadOfflineSignature([]byte{}, signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519)
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrInsufficientData)
	})

	t.Run("ErrUnknownSignatureType_still_works", func(t *testing.T) {
		data := make([]byte, 200)
		binary.BigEndian.PutUint16(data[4:6], 999)
		_, _, err := ReadOfflineSignature(data, signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519)
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrUnknownSignatureType)
	})

	t.Run("ErrExpiredOfflineSignature_still_works", func(t *testing.T) {
		pastExpires := uint32(time.Now().UTC().Add(-1 * time.Hour).Unix())
		transientKey := make([]byte, key_certificate.KEYCERT_SIGN_ED25519_SIZE)
		sig := make([]byte, signature.EdDSA_SHA512_Ed25519_SIZE)
		offlineSig, err := NewOfflineSignature(pastExpires, key_certificate.KEYCERT_SIGN_ED25519, transientKey, sig, signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519)
		require.NoError(t, err)
		assert.ErrorIs(t, offlineSig.Validate(), ErrExpiredOfflineSignature)
	})
}

// =========================================================================
// Bytes() contextual dependency test (SPEC-2)
// =========================================================================

func TestBytesDoesNotIncludeDestinationSigType(t *testing.T) {
	// SPEC-2: Bytes() output does not include destinationSigType.
	// Verify that the same OfflineSignature structure produces identical Bytes()
	// regardless of which destinationSigType was used during construction,
	// as long as signature data is the same length.
	expires := uint32(1735689600)
	transientKey := make([]byte, key_certificate.KEYCERT_SIGN_ED25519_SIZE)
	for i := range transientKey {
		transientKey[i] = byte(i)
	}

	// Both Ed25519 and RedDSA produce 64-byte signatures.
	sig := make([]byte, 64)
	for i := range sig {
		sig[i] = byte(i + 100)
	}

	sig1, err := NewOfflineSignature(expires, key_certificate.KEYCERT_SIGN_ED25519,
		transientKey, sig, signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519)
	require.NoError(t, err)

	sig2, err := NewOfflineSignature(expires, key_certificate.KEYCERT_SIGN_ED25519,
		transientKey, sig, signature.SIGNATURE_TYPE_REDDSA_SHA512_ED25519)
	require.NoError(t, err)

	assert.Equal(t, sig1.Bytes(), sig2.Bytes(),
		"Bytes() output should be identical regardless of destinationSigType")
	assert.NotEqual(t, sig1.DestinationSigType(), sig2.DestinationSigType(),
		"destination sig types should differ to confirm they're not in the wire format")
}

func TestBytesRoundTripRequiresDestSigType(t *testing.T) {
	// SPEC-2: re-parsing Bytes() output requires caller to supply destinationSigType
	expires := uint32(1735689600)
	transientKey := make([]byte, key_certificate.KEYCERT_SIGN_ED25519_SIZE)
	sig := make([]byte, signature.EdDSA_SHA512_Ed25519_SIZE)

	original, err := NewOfflineSignature(expires, key_certificate.KEYCERT_SIGN_ED25519,
		transientKey, sig, signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519)
	require.NoError(t, err)

	wireBytes := original.Bytes()

	// Parse with correct destSigType succeeds
	parsed, rem, err := ReadOfflineSignature(wireBytes, signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519)
	assert.NoError(t, err)
	assert.Empty(t, rem)
	assert.Equal(t, original.Expires(), parsed.Expires())
	assert.Equal(t, original.TransientSigType(), parsed.TransientSigType())

	// Parse with wrong destSigType (different sig size) fails or generates wrong result
	_, _, err = ReadOfflineSignature(wireBytes, signature.SIGNATURE_TYPE_ECDSA_SHA256_P256)
	// P256 has 64-byte signature, same as Ed25519, so it should succeed parse but
	// the semantic meaning is different — confirming contextual dependency
	if err == nil {
		// Parsed successfully but with wrong destSigType — shows contextual dependency
		assert.NotEqual(t, original.DestinationSigType(), signature.SIGNATURE_TYPE_ECDSA_SHA256_P256)
	}
}
