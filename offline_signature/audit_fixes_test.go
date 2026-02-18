// Package offline_signature tests for audit findings.
package offline_signature

import (
	"crypto/ed25519"
	"encoding/binary"
	"testing"
	"time"

	"github.com/go-i2p/common/key_certificate"
	"github.com/go-i2p/common/signature"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Finding 1: Defensive copy regression test ---

// TestNewOfflineSignatureDefensiveCopy confirms that NewOfflineSignature makes
// defensive copies of input slices, so caller mutations don't corrupt the struct.
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

// --- Finding 2: SignedData() tests ---

// TestSignedData verifies that SignedData() produces the correct byte sequence
// per the I2P spec: expires(4) || sigtype(2) || transient_public_key(variable).
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
		// DSA_SHA1 has 128-byte public key
		dsaKey := make([]byte, key_certificate.KEYCERT_SIGN_DSA_SHA1_SIZE)
		dsaSig := make([]byte, signature.DSA_SHA1_SIZE)
		dsa, err := NewOfflineSignature(expires, key_certificate.KEYCERT_SIGN_DSA_SHA1, dsaKey, dsaSig, signature.SIGNATURE_TYPE_DSA_SHA1)
		require.NoError(t, err)
		sd := dsa.SignedData()
		assert.Equal(t, EXPIRES_SIZE+SIGTYPE_SIZE+key_certificate.KEYCERT_SIGN_DSA_SHA1_SIZE, len(sd))
	})
}

// --- Finding 3: VerifySignature() tests ---

// TestVerifySignatureEd25519 tests VerifySignature with Ed25519 keys.
func TestVerifySignatureEd25519(t *testing.T) {
	pubKey, privKey, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	expires := uint32(time.Now().UTC().Add(24 * time.Hour).Unix())
	transientKey := make([]byte, key_certificate.KEYCERT_SIGN_ED25519_SIZE)
	for i := range transientKey {
		transientKey[i] = byte(i)
	}

	offlineSig, err := CreateOfflineSignature(
		expires,
		key_certificate.KEYCERT_SIGN_ED25519,
		transientKey,
		privKey,
		signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519,
	)
	require.NoError(t, err)

	t.Run("valid_signature", func(t *testing.T) {
		valid, err := offlineSig.VerifySignature(pubKey)
		assert.NoError(t, err)
		assert.True(t, valid, "signature should verify with correct public key")
	})

	t.Run("wrong_public_key", func(t *testing.T) {
		otherPub, _, _ := ed25519.GenerateKey(nil)
		valid, err := offlineSig.VerifySignature(otherPub)
		assert.NoError(t, err)
		assert.False(t, valid, "signature should not verify with wrong public key")
	})

	t.Run("invalid_key_size", func(t *testing.T) {
		_, err := offlineSig.VerifySignature([]byte{1, 2, 3})
		assert.Error(t, err, "should reject invalid key size")
	})
}

// TestVerifySignatureRedDSA tests VerifySignature with RedDSA type (same verification as Ed25519).
func TestVerifySignatureRedDSA(t *testing.T) {
	pubKey, privKey, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	expires := uint32(time.Now().UTC().Add(24 * time.Hour).Unix())
	transientKey := make([]byte, key_certificate.KEYCERT_SIGN_ED25519_SIZE)

	offlineSig, err := CreateOfflineSignature(
		expires,
		key_certificate.KEYCERT_SIGN_REDDSA_ED25519,
		transientKey,
		privKey,
		signature.SIGNATURE_TYPE_REDDSA_SHA512_ED25519,
	)
	require.NoError(t, err)

	valid, err := offlineSig.VerifySignature(pubKey)
	assert.NoError(t, err)
	assert.True(t, valid, "RedDSA signature should verify with correct public key")
}

// TestVerifySignatureUnsupportedType tests that verification returns an error for
// unsupported legacy signature types.
func TestVerifySignatureUnsupportedType(t *testing.T) {
	dsaKey := make([]byte, key_certificate.KEYCERT_SIGN_DSA_SHA1_SIZE)
	dsaSig := make([]byte, signature.DSA_SHA1_SIZE)

	offlineSig, err := NewOfflineSignature(
		uint32(time.Now().UTC().Add(24*time.Hour).Unix()),
		key_certificate.KEYCERT_SIGN_DSA_SHA1,
		dsaKey, dsaSig,
		signature.SIGNATURE_TYPE_DSA_SHA1,
	)
	require.NoError(t, err)

	_, err = offlineSig.VerifySignature(make([]byte, 128))
	assert.Error(t, err, "should error for unsupported destination type")
	assert.Contains(t, err.Error(), "not implemented", "error should mention not implemented")
}

// --- Finding 4: CreateOfflineSignature() tests ---

// TestCreateOfflineSignatureEd25519 tests the full creation flow.
func TestCreateOfflineSignatureEd25519(t *testing.T) {
	pubKey, privKey, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	expires := uint32(time.Now().UTC().Add(24 * time.Hour).Unix())
	transientKey := make([]byte, key_certificate.KEYCERT_SIGN_ED25519_SIZE)
	for i := range transientKey {
		transientKey[i] = byte(i)
	}

	offlineSig, err := CreateOfflineSignature(
		expires,
		key_certificate.KEYCERT_SIGN_ED25519,
		transientKey,
		privKey,
		signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519,
	)
	require.NoError(t, err)

	// Verify the fields
	assert.Equal(t, expires, offlineSig.Expires())
	assert.Equal(t, uint16(key_certificate.KEYCERT_SIGN_ED25519), offlineSig.TransientSigType())
	assert.Equal(t, transientKey, offlineSig.TransientPublicKey())

	// Verify the signature is correct
	valid, err := offlineSig.VerifySignature(pubKey)
	assert.NoError(t, err)
	assert.True(t, valid, "created signature should verify")

	// Validate round-trip
	serialized := offlineSig.Bytes()
	parsed, rem, err := ReadOfflineSignature(serialized, signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519)
	require.NoError(t, err)
	assert.Empty(t, rem)

	valid2, err := parsed.VerifySignature(pubKey)
	assert.NoError(t, err)
	assert.True(t, valid2, "round-tripped signature should still verify")
}

// TestCreateOfflineSignatureInvalidParams tests error paths.
func TestCreateOfflineSignatureInvalidParams(t *testing.T) {
	_, privKey, _ := ed25519.GenerateKey(nil)
	transientKey := make([]byte, key_certificate.KEYCERT_SIGN_ED25519_SIZE)

	t.Run("zero_expires", func(t *testing.T) {
		_, err := CreateOfflineSignature(0, key_certificate.KEYCERT_SIGN_ED25519, transientKey, privKey, signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "non-zero")
	})

	t.Run("unknown_transient_type", func(t *testing.T) {
		_, err := CreateOfflineSignature(12345, 999, transientKey, privKey, signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519)
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrUnknownSignatureType)
	})

	t.Run("wrong_transient_key_size", func(t *testing.T) {
		_, err := CreateOfflineSignature(12345, key_certificate.KEYCERT_SIGN_ED25519, []byte{1, 2, 3}, privKey, signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "size mismatch")
	})

	t.Run("unknown_destination_type", func(t *testing.T) {
		_, err := CreateOfflineSignature(12345, key_certificate.KEYCERT_SIGN_ED25519, transientKey, privKey, 999)
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrUnknownSignatureType)
	})

	t.Run("unsupported_signing_type", func(t *testing.T) {
		dsaKey := make([]byte, key_certificate.KEYCERT_SIGN_DSA_SHA1_SIZE)
		_, err := CreateOfflineSignature(12345, key_certificate.KEYCERT_SIGN_DSA_SHA1, dsaKey, privKey, signature.SIGNATURE_TYPE_DSA_SHA1)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not implemented")
	})
}

// --- Finding 5: Ed25519ph (type 8) test ---

// TestReadOfflineSignatureEd25519ph tests parsing with Ed25519ph transient key.
func TestReadOfflineSignatureEd25519ph(t *testing.T) {
	expires := uint32(1735689600)
	transientSigType := uint16(key_certificate.KEYCERT_SIGN_ED25519PH)
	transientKeySize := key_certificate.KEYCERT_SIGN_ED25519PH_SIZE // 32 bytes
	destSigType := uint16(signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519)
	sigSize := signature.EdDSA_SHA512_Ed25519_SIZE // 64 bytes

	data := make([]byte, EXPIRES_SIZE+SIGTYPE_SIZE+transientKeySize+sigSize)
	binary.BigEndian.PutUint32(data[0:4], expires)
	binary.BigEndian.PutUint16(data[4:6], transientSigType)
	for i := 0; i < transientKeySize; i++ {
		data[6+i] = byte(i)
	}

	offlineSig, remainder, err := ReadOfflineSignature(data, destSigType)

	assert.NoError(t, err)
	assert.Empty(t, remainder)
	assert.Equal(t, expires, offlineSig.Expires())
	assert.Equal(t, transientSigType, offlineSig.TransientSigType())
	assert.Equal(t, transientKeySize, len(offlineSig.TransientPublicKey()))
	assert.Equal(t, sigSize, len(offlineSig.Signature()))
}

// TestEd25519phDestinationType tests parsing + validation with Ed25519ph destination type.
func TestEd25519phDestinationType(t *testing.T) {
	expires := uint32(time.Now().UTC().Add(24 * time.Hour).Unix())
	transientKeySize := key_certificate.KEYCERT_SIGN_ED25519_SIZE
	destSigType := uint16(signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519PH)
	sigSize := signature.EdDSA_SHA512_Ed25519ph_SIZE

	data := make([]byte, EXPIRES_SIZE+SIGTYPE_SIZE+transientKeySize+sigSize)
	binary.BigEndian.PutUint32(data[0:4], expires)
	binary.BigEndian.PutUint16(data[4:6], key_certificate.KEYCERT_SIGN_ED25519)

	offlineSig, remainder, err := ReadOfflineSignature(data, destSigType)

	assert.NoError(t, err)
	assert.Empty(t, remainder)
	assert.NoError(t, offlineSig.ValidateStructure())
}

// --- Finding 6: All signature types tests ---

// TestReadOfflineSignatureAllTypes tests parsing with every supported signature type combination.
func TestReadOfflineSignatureAllTypes(t *testing.T) {
	testCases := []struct {
		name               string
		transientSigType   uint16
		destinationSigType uint16
		transientKeySize   int
		signatureSize      int
	}{
		{"DSA_SHA1_transient_DSA_dest", key_certificate.KEYCERT_SIGN_DSA_SHA1, signature.SIGNATURE_TYPE_DSA_SHA1, key_certificate.KEYCERT_SIGN_DSA_SHA1_SIZE, signature.DSA_SHA1_SIZE},
		{"P256_transient_P256_dest", key_certificate.KEYCERT_SIGN_P256, signature.SIGNATURE_TYPE_ECDSA_SHA256_P256, key_certificate.KEYCERT_SIGN_P256_SIZE, signature.ECDSA_SHA256_P256_SIZE},
		{"P384_transient_P384_dest", key_certificate.KEYCERT_SIGN_P384, signature.SIGNATURE_TYPE_ECDSA_SHA384_P384, key_certificate.KEYCERT_SIGN_P384_SIZE, signature.ECDSA_SHA384_P384_SIZE},
		{"P521_transient_P521_dest", key_certificate.KEYCERT_SIGN_P521, signature.SIGNATURE_TYPE_ECDSA_SHA512_P521, key_certificate.KEYCERT_SIGN_P521_SIZE, signature.ECDSA_SHA512_P521_SIZE},
		{"RSA2048_transient_RSA2048_dest", key_certificate.KEYCERT_SIGN_RSA2048, signature.SIGNATURE_TYPE_RSA_SHA256_2048, key_certificate.KEYCERT_SIGN_RSA2048_SIZE, signature.RSA_SHA256_2048_SIZE},
		{"RSA3072_transient_RSA3072_dest", key_certificate.KEYCERT_SIGN_RSA3072, signature.SIGNATURE_TYPE_RSA_SHA384_3072, key_certificate.KEYCERT_SIGN_RSA3072_SIZE, signature.RSA_SHA384_3072_SIZE},
		{"RSA4096_transient_RSA4096_dest", key_certificate.KEYCERT_SIGN_RSA4096, signature.SIGNATURE_TYPE_RSA_SHA512_4096, key_certificate.KEYCERT_SIGN_RSA4096_SIZE, signature.RSA_SHA512_4096_SIZE},
		{"Ed25519_transient_Ed25519_dest", key_certificate.KEYCERT_SIGN_ED25519, signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519, key_certificate.KEYCERT_SIGN_ED25519_SIZE, signature.EdDSA_SHA512_Ed25519_SIZE},
		{"Ed25519ph_transient_Ed25519ph_dest", key_certificate.KEYCERT_SIGN_ED25519PH, signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519PH, key_certificate.KEYCERT_SIGN_ED25519PH_SIZE, signature.EdDSA_SHA512_Ed25519ph_SIZE},
		{"RedDSA_transient_RedDSA_dest", key_certificate.KEYCERT_SIGN_REDDSA_ED25519, signature.SIGNATURE_TYPE_REDDSA_SHA512_ED25519, key_certificate.KEYCERT_SIGN_ED25519_SIZE, signature.RedDSA_SHA512_Ed25519_SIZE},
		// Mixed type combinations
		{"Ed25519_transient_DSA_dest", key_certificate.KEYCERT_SIGN_ED25519, signature.SIGNATURE_TYPE_DSA_SHA1, key_certificate.KEYCERT_SIGN_ED25519_SIZE, signature.DSA_SHA1_SIZE},
		{"P256_transient_Ed25519_dest", key_certificate.KEYCERT_SIGN_P256, signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519, key_certificate.KEYCERT_SIGN_P256_SIZE, signature.EdDSA_SHA512_Ed25519_SIZE},
		{"RedDSA_transient_Ed25519_dest", key_certificate.KEYCERT_SIGN_REDDSA_ED25519, signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519, key_certificate.KEYCERT_SIGN_ED25519_SIZE, signature.EdDSA_SHA512_Ed25519_SIZE},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			expires := uint32(1735689600)
			totalSize := EXPIRES_SIZE + SIGTYPE_SIZE + tc.transientKeySize + tc.signatureSize
			data := make([]byte, totalSize)
			binary.BigEndian.PutUint32(data[0:4], expires)
			binary.BigEndian.PutUint16(data[4:6], tc.transientSigType)

			offlineSig, remainder, err := ReadOfflineSignature(data, tc.destinationSigType)

			assert.NoError(t, err, "should parse without error")
			assert.Empty(t, remainder, "should have no remainder")
			assert.Equal(t, expires, offlineSig.Expires())
			assert.Equal(t, tc.transientSigType, offlineSig.TransientSigType())
			assert.Equal(t, tc.transientKeySize, len(offlineSig.TransientPublicKey()))
			assert.Equal(t, tc.signatureSize, len(offlineSig.Signature()))
		})
	}
}

// TestValidateAllSignatureTypes tests Validate() with all 10 supported signature type combinations.
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

// --- Finding 8: Fuzz test ---

// FuzzReadOfflineSignature exercises ReadOfflineSignature with random inputs.
func FuzzReadOfflineSignature(f *testing.F) {
	// Seed with valid Ed25519 OfflineSignature
	validData := make([]byte, 102)
	binary.BigEndian.PutUint32(validData[0:4], 1735689600)
	binary.BigEndian.PutUint16(validData[4:6], key_certificate.KEYCERT_SIGN_ED25519)
	f.Add(validData, uint16(signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519))

	// Empty data
	f.Add([]byte{}, uint16(signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519))

	// Only header
	header := make([]byte, 6)
	binary.BigEndian.PutUint16(header[4:6], key_certificate.KEYCERT_SIGN_ED25519)
	f.Add(header, uint16(signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519))

	// Truncated after transient key
	truncated := make([]byte, 38) // 4+2+32
	binary.BigEndian.PutUint16(truncated[4:6], key_certificate.KEYCERT_SIGN_ED25519)
	f.Add(truncated, uint16(signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519))

	// Unknown transient type
	unknownType := make([]byte, 200)
	binary.BigEndian.PutUint16(unknownType[4:6], 999)
	f.Add(unknownType, uint16(signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519))

	// Unknown destination type
	f.Add(validData, uint16(999))

	// Very large data
	large := make([]byte, 1024)
	binary.BigEndian.PutUint16(large[4:6], key_certificate.KEYCERT_SIGN_ED25519)
	f.Add(large, uint16(signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519))

	// RedDSA type
	redDSAData := make([]byte, 102)
	binary.BigEndian.PutUint32(redDSAData[0:4], 1735689600)
	binary.BigEndian.PutUint16(redDSAData[4:6], key_certificate.KEYCERT_SIGN_REDDSA_ED25519)
	f.Add(redDSAData, uint16(signature.SIGNATURE_TYPE_REDDSA_SHA512_ED25519))

	// Ed25519ph type
	phData := make([]byte, 102)
	binary.BigEndian.PutUint32(phData[0:4], 1735689600)
	binary.BigEndian.PutUint16(phData[4:6], key_certificate.KEYCERT_SIGN_ED25519PH)
	f.Add(phData, uint16(signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519PH))

	// P384 transient
	p384Data := make([]byte, EXPIRES_SIZE+SIGTYPE_SIZE+key_certificate.KEYCERT_SIGN_P384_SIZE+signature.ECDSA_SHA384_P384_SIZE)
	binary.BigEndian.PutUint16(p384Data[4:6], key_certificate.KEYCERT_SIGN_P384)
	f.Add(p384Data, uint16(signature.SIGNATURE_TYPE_ECDSA_SHA384_P384))

	f.Fuzz(func(t *testing.T, data []byte, destSigType uint16) {
		offlineSig, remainder, err := ReadOfflineSignature(data, destSigType)
		if err != nil {
			// On error, no panic is the only requirement
			return
		}

		// If parsing succeeded, validate structural consistency
		assert.Greater(t, offlineSig.Len(), 0, "Len should be positive")
		assert.NotNil(t, offlineSig.TransientPublicKey(), "transient key should not be nil")
		assert.NotNil(t, offlineSig.Signature(), "signature should not be nil")

		// Verify round-trip serialization
		serialized := offlineSig.Bytes()
		parsed, _, err2 := ReadOfflineSignature(serialized, destSigType)
		if err2 == nil {
			assert.Equal(t, offlineSig.Expires(), parsed.Expires())
			assert.Equal(t, offlineSig.TransientSigType(), parsed.TransientSigType())
			assert.Equal(t, offlineSig.TransientPublicKey(), parsed.TransientPublicKey())
			assert.Equal(t, offlineSig.Signature(), parsed.Signature())
		}

		// Remainder should have correct length
		expectedConsumed := EXPIRES_SIZE + SIGTYPE_SIZE + len(offlineSig.TransientPublicKey()) + len(offlineSig.Signature())
		assert.Equal(t, len(data)-expectedConsumed, len(remainder))
	})
}

// --- Finding 10: OFFLINE_SIGNATURE_EDDSA_SIZE constant test ---

// TestOfflineSignatureEddsaSize verifies the EDDSA_SIZE constant and its relationship
// to OFFLINE_SIGNATURE_MIN_SIZE (deprecated alias).
func TestOfflineSignatureEddsaSize(t *testing.T) {
	t.Run("eddsa_size_value", func(t *testing.T) {
		expected := EXPIRES_SIZE + SIGTYPE_SIZE + key_certificate.KEYCERT_SIGN_ED25519_SIZE + signature.EdDSA_SHA512_Ed25519_SIZE
		assert.Equal(t, expected, OFFLINE_SIGNATURE_EDDSA_SIZE,
			"EDDSA_SIZE should be 4+2+32+64 = 102")
	})

	t.Run("deprecated_alias", func(t *testing.T) {
		assert.Equal(t, OFFLINE_SIGNATURE_EDDSA_SIZE, OFFLINE_SIGNATURE_MIN_SIZE,
			"OFFLINE_SIGNATURE_MIN_SIZE should equal OFFLINE_SIGNATURE_EDDSA_SIZE (deprecated alias)")
	})

	t.Run("mixed_type_smaller_than_eddsa", func(t *testing.T) {
		// Ed25519 transient (32 bytes) + DSA_SHA1 signature (40 bytes) = 78 bytes
		mixedSize := EXPIRES_SIZE + SIGTYPE_SIZE + key_certificate.KEYCERT_SIGN_ED25519_SIZE + signature.DSA_SHA1_SIZE
		assert.Less(t, mixedSize, OFFLINE_SIGNATURE_EDDSA_SIZE,
			"mixed-type combination (Ed25519+DSA_SHA1) is smaller than EDDSA_SIZE, "+
				"proving the constant is not the true minimum across all type combinations")
	})
}

// --- Finding 11: ValidateStructure() tests ---

// TestValidateStructure tests structural validation independent of expiration.
func TestValidateStructure(t *testing.T) {
	t.Run("valid_expired_signature", func(t *testing.T) {
		// An expired but structurally valid signature should pass ValidateStructure
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

		// ValidateStructure should pass (ignores expiration)
		assert.NoError(t, offlineSig.ValidateStructure(),
			"expired signature should pass structural validation")

		// But Validate should fail (checks expiration)
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
			transientPublicKey: make([]byte, 16), // wrong size
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
			signature:          make([]byte, 32), // wrong size
			destinationSigType: signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519,
		}
		assert.Error(t, offlineSig.ValidateStructure())
		assert.Contains(t, offlineSig.ValidateStructure().Error(), "signature size mismatch")
	})
}
