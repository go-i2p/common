package offline_signature

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	cryptorand "crypto/rand"
	"encoding/binary"
	"fmt"
	"testing"
	"time"

	"github.com/go-i2p/common/key_certificate"
	"github.com/go-i2p/common/signature"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =========================================================================
// Round-trip serialization Tests
// =========================================================================

func TestOfflineSignatureSerialization(t *testing.T) {
	expires := uint32(1735689600)
	transientSigType := key_certificate.KEYCERT_SIGN_ED25519
	transientKey := make([]byte, key_certificate.KEYCERT_SIGN_ED25519_SIZE)
	sig := make([]byte, signature.EdDSA_SHA512_Ed25519_SIZE)
	destSigType := signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519

	for i := range transientKey {
		transientKey[i] = byte(i)
	}
	for i := range sig {
		sig[i] = byte(0xFF - i)
	}

	original, err := NewOfflineSignature(expires, uint16(transientSigType), transientKey, sig, uint16(destSigType))
	assert.NoError(t, err)

	serialized := original.Bytes()

	parsed, remainder, err := ReadOfflineSignature(serialized, uint16(destSigType))

	assert.NoError(t, err, "should parse serialized data without error")
	assert.Empty(t, remainder, "should have no remainder")
	assert.Equal(t, original.Expires(), parsed.Expires())
	assert.Equal(t, original.TransientSigType(), parsed.TransientSigType())
	assert.Equal(t, original.TransientPublicKey(), parsed.TransientPublicKey())
	assert.Equal(t, original.Signature(), parsed.Signature())
	assert.Equal(t, original.DestinationSigType(), parsed.DestinationSigType())
	assert.Equal(t, original.Len(), len(serialized))
}

func TestOfflineSignatureValidateRoundTrip(t *testing.T) {
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
		transientKey, sig,
		signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519,
	)
	assert.NoError(t, err)
	assert.NoError(t, original.Validate(), "original should be valid")
	assert.True(t, original.IsValid(), "original should pass IsValid()")

	serialized := original.Bytes()
	parsed, remainder, err := ReadOfflineSignature(serialized, signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519)
	assert.NoError(t, err)
	assert.Empty(t, remainder)

	assert.NoError(t, parsed.Validate(), "parsed signature should be valid")
	assert.True(t, parsed.IsValid(), "parsed signature should pass IsValid()")
}

// =========================================================================
// VerifySignature Tests
// =========================================================================

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

func TestVerifySignatureRedDSA(t *testing.T) {
	pubKey, privKey, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	expires := uint32(time.Now().UTC().Add(24 * time.Hour).Unix())
	transientKey := make([]byte, key_certificate.KEYCERT_SIGN_ED25519_SIZE)

	// CreateOfflineSignature rejects RedDSA (type 11): standard Ed25519 signing is
	// not spec-compliant for RedDSA (missing randomised nonces). Build signed data
	// manually so we can confirm that VerifySignature still works on the correct path.
	signedData := make([]byte, EXPIRES_SIZE+SIGTYPE_SIZE+len(transientKey))
	binary.BigEndian.PutUint32(signedData[0:4], expires)
	binary.BigEndian.PutUint16(signedData[4:6], key_certificate.KEYCERT_SIGN_REDDSA_ED25519)
	copy(signedData[6:], transientKey)
	sigBytes := ed25519.Sign(privKey, signedData)

	offlineSig, err := NewOfflineSignature(
		expires,
		key_certificate.KEYCERT_SIGN_REDDSA_ED25519,
		transientKey,
		sigBytes,
		signature.SIGNATURE_TYPE_REDDSA_SHA512_ED25519,
	)
	require.NoError(t, err)

	valid, vErr := offlineSig.VerifySignature(pubKey)
	assert.NoError(t, vErr)
	assert.True(t, valid, "RedDSA signature should verify: same curve as Ed25519")
}

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

// =========================================================================
// CreateOfflineSignature Tests
// =========================================================================

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

	assert.Equal(t, expires, offlineSig.Expires())
	assert.Equal(t, uint16(key_certificate.KEYCERT_SIGN_ED25519), offlineSig.TransientSigType())
	assert.Equal(t, transientKey, offlineSig.TransientPublicKey())

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

// =========================================================================
// Ed25519ph Tests
// =========================================================================

func TestReadOfflineSignatureEd25519ph(t *testing.T) {
	expires := uint32(1735689600)
	transientSigType := uint16(key_certificate.KEYCERT_SIGN_ED25519PH)
	transientKeySize := key_certificate.KEYCERT_SIGN_ED25519PH_SIZE
	destSigType := uint16(signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519)
	sigSize := signature.EdDSA_SHA512_Ed25519_SIZE

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

// =========================================================================
// All signature type combinations
// =========================================================================

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

// =========================================================================
// Benchmarks
// =========================================================================

func BenchmarkReadOfflineSignature(b *testing.B) {
	data := make([]byte, 102)
	binary.BigEndian.PutUint32(data[0:4], uint32(1735689600))
	binary.BigEndian.PutUint16(data[4:6], key_certificate.KEYCERT_SIGN_ED25519)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = ReadOfflineSignature(data, signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519)
	}
}

func BenchmarkOfflineSignatureBytes(b *testing.B) {
	transientKey := make([]byte, key_certificate.KEYCERT_SIGN_ED25519_SIZE)
	sig := make([]byte, signature.EdDSA_SHA512_Ed25519_SIZE)

	offlineSig, _ := NewOfflineSignature(
		uint32(1735689600),
		key_certificate.KEYCERT_SIGN_ED25519,
		transientKey, sig,
		signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519,
	)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = offlineSig.Bytes()
	}
}

// =========================================================================
// Ed25519ph round-trip test (CreateOfflineSignature → VerifySignature)
// Validates the SHA-512 pre-hashing for both sign and verify paths
// =========================================================================

func TestCreateAndVerifyOfflineSignatureEd25519ph(t *testing.T) {
	pubKey, privKey, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	expires := uint32(time.Now().UTC().Add(24 * time.Hour).Unix())
	transientKey := make([]byte, key_certificate.KEYCERT_SIGN_ED25519_SIZE)
	for i := range transientKey {
		transientKey[i] = byte(i + 1)
	}

	t.Run("create_and_verify_ed25519ph", func(t *testing.T) {
		offlineSig, err := CreateOfflineSignature(
			expires,
			key_certificate.KEYCERT_SIGN_ED25519,
			transientKey,
			privKey,
			signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519PH,
		)
		require.NoError(t, err)

		assert.Equal(t, expires, offlineSig.Expires())
		assert.Equal(t, uint16(key_certificate.KEYCERT_SIGN_ED25519), offlineSig.TransientSigType())
		assert.Equal(t, uint16(signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519PH), offlineSig.DestinationSigType())

		valid, err := offlineSig.VerifySignature(pubKey)
		assert.NoError(t, err)
		assert.True(t, valid, "Ed25519ph signature should verify with correct public key")
	})

	t.Run("ed25519ph_wrong_key_fails", func(t *testing.T) {
		offlineSig, err := CreateOfflineSignature(
			expires,
			key_certificate.KEYCERT_SIGN_ED25519,
			transientKey,
			privKey,
			signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519PH,
		)
		require.NoError(t, err)

		otherPub, _, _ := ed25519.GenerateKey(nil)
		valid, err := offlineSig.VerifySignature(otherPub)
		assert.NoError(t, err)
		assert.False(t, valid, "Ed25519ph signature should not verify with wrong public key")
	})

	t.Run("ed25519ph_round_trip_serialization", func(t *testing.T) {
		offlineSig, err := CreateOfflineSignature(
			expires,
			key_certificate.KEYCERT_SIGN_ED25519,
			transientKey,
			privKey,
			signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519PH,
		)
		require.NoError(t, err)

		// Serialize and re-parse
		serialized := offlineSig.Bytes()
		parsed, rem, err := ReadOfflineSignature(serialized, signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519PH)
		require.NoError(t, err)
		assert.Empty(t, rem)

		// Verify the re-parsed signature
		valid, err := parsed.VerifySignature(pubKey)
		assert.NoError(t, err)
		assert.True(t, valid, "round-tripped Ed25519ph signature should still verify")
	})

	t.Run("ed25519ph_transient_ed25519ph_dest", func(t *testing.T) {
		// Ed25519ph transient key + Ed25519ph destination
		phTransientKey := make([]byte, key_certificate.KEYCERT_SIGN_ED25519PH_SIZE)
		for i := range phTransientKey {
			phTransientKey[i] = byte(0xAA ^ byte(i))
		}
		offlineSig, err := CreateOfflineSignature(
			expires,
			key_certificate.KEYCERT_SIGN_ED25519PH,
			phTransientKey,
			privKey,
			signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519PH,
		)
		require.NoError(t, err)

		valid, err := offlineSig.VerifySignature(pubKey)
		assert.NoError(t, err)
		assert.True(t, valid, "Ed25519ph transient + Ed25519ph destination should verify")
	})
}

// =========================================================================
// VerifySignature with tampered fields
// Confirms that SignedData() correctly covers all fields
// =========================================================================

func TestVerifySignatureTamperedFields(t *testing.T) {
	pubKey, privKey, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	expires := uint32(time.Now().UTC().Add(24 * time.Hour).Unix())
	transientKey := make([]byte, key_certificate.KEYCERT_SIGN_ED25519_SIZE)
	for i := range transientKey {
		transientKey[i] = byte(i + 1)
	}

	// Create a valid signature
	offlineSig, err := CreateOfflineSignature(
		expires,
		key_certificate.KEYCERT_SIGN_ED25519,
		transientKey,
		privKey,
		signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519,
	)
	require.NoError(t, err)

	// Verify original is valid
	valid, err := offlineSig.VerifySignature(pubKey)
	require.NoError(t, err)
	require.True(t, valid, "original signature should be valid")

	t.Run("tampered_expires", func(t *testing.T) {
		tampered := OfflineSignature{
			expires:            offlineSig.expires + 1,
			sigtype:            offlineSig.sigtype,
			transientPublicKey: offlineSig.TransientPublicKey(),
			signature:          offlineSig.Signature(),
			destinationSigType: offlineSig.destinationSigType,
		}
		valid, err := tampered.VerifySignature(pubKey)
		assert.NoError(t, err)
		assert.False(t, valid, "modified expires should invalidate signature")
	})

	t.Run("tampered_sigtype", func(t *testing.T) {
		// Change sigtype to Ed25519ph (same key size, so structural validation passes)
		tampered := OfflineSignature{
			expires:            offlineSig.expires,
			sigtype:            key_certificate.KEYCERT_SIGN_ED25519PH,
			transientPublicKey: offlineSig.TransientPublicKey(),
			signature:          offlineSig.Signature(),
			destinationSigType: offlineSig.destinationSigType,
		}
		valid, err := tampered.VerifySignature(pubKey)
		assert.NoError(t, err)
		assert.False(t, valid, "modified sigtype should invalidate signature")
	})

	t.Run("tampered_transient_key", func(t *testing.T) {
		tamperedKey := offlineSig.TransientPublicKey()
		tamperedKey[0] ^= 0xFF // Flip bits in first byte
		tampered := OfflineSignature{
			expires:            offlineSig.expires,
			sigtype:            offlineSig.sigtype,
			transientPublicKey: tamperedKey,
			signature:          offlineSig.Signature(),
			destinationSigType: offlineSig.destinationSigType,
		}
		valid, err := tampered.VerifySignature(pubKey)
		assert.NoError(t, err)
		assert.False(t, valid, "modified transient key should invalidate signature")
	})

	t.Run("tampered_signature_bytes", func(t *testing.T) {
		tamperedSig := offlineSig.Signature()
		tamperedSig[0] ^= 0xFF // Flip bits in first byte
		tampered := OfflineSignature{
			expires:            offlineSig.expires,
			sigtype:            offlineSig.sigtype,
			transientPublicKey: offlineSig.TransientPublicKey(),
			signature:          tamperedSig,
			destinationSigType: offlineSig.destinationSigType,
		}
		valid, err := tampered.VerifySignature(pubKey)
		assert.NoError(t, err)
		assert.False(t, valid, "tampered signature bytes should not verify")
	})
}

// =========================================================================
// RedDSA signing returns explicit error (AUDIT BUG fix: was silently using Ed25519)
// =========================================================================

func TestRedDSASigningReturnsError(t *testing.T) {
	_, privKey, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	expires := uint32(time.Now().UTC().Add(24 * time.Hour).Unix())
	transientKey := make([]byte, key_certificate.KEYCERT_SIGN_ED25519_SIZE)

	// CreateOfflineSignature must now REJECT RedDSA signing.  Standard Ed25519
	// signatures are not spec-compliant for RedDSA (no randomised per-message nonces).
	t.Run("reddsa_create_returns_error", func(t *testing.T) {
		_, cerr := CreateOfflineSignature(
			expires,
			key_certificate.KEYCERT_SIGN_REDDSA_ED25519,
			transientKey,
			privKey,
			signature.SIGNATURE_TYPE_REDDSA_SHA512_ED25519,
		)
		require.Error(t, cerr, "CreateOfflineSignature should reject RedDSA type")
		assert.Contains(t, cerr.Error(), "not implemented",
			"error should mention 'not implemented' so callers use a dedicated RedDSA library")
	})

	t.Run("reddsa_verify_still_works_with_ed25519_sig", func(t *testing.T) {
		// VerifySignature for RedDSA type 11 is valid: the curve is identical to
		// Ed25519. Build a signed-data blob manually and sign with ed25519:
		pubKey, priv2, keyErr := ed25519.GenerateKey(nil)
		require.NoError(t, keyErr)
		signedData := make([]byte, EXPIRES_SIZE+SIGTYPE_SIZE+len(transientKey))
		binary.BigEndian.PutUint32(signedData[0:4], expires)
		binary.BigEndian.PutUint16(signedData[4:6], key_certificate.KEYCERT_SIGN_REDDSA_ED25519)
		copy(signedData[6:], transientKey)
		sigBytes := ed25519.Sign(priv2, signedData)
		offlineSig, newErr := NewOfflineSignature(
			expires,
			key_certificate.KEYCERT_SIGN_REDDSA_ED25519,
			transientKey,
			sigBytes,
			signature.SIGNATURE_TYPE_REDDSA_SHA512_ED25519,
		)
		require.NoError(t, newErr)
		valid, vErr := offlineSig.VerifySignature(pubKey)
		assert.NoError(t, vErr)
		assert.True(t, valid, "RedDSA verification uses Ed25519 curve: should succeed")
	})
}

// =========================================================================
// VerifySignature type coverage
// =========================================================================

// TestVerifySignatureLegacyTypes confirms that DSA-SHA1 and RSA destination types
// return explicit "not implemented" errors (legacy algorithms are not supported).
func TestVerifySignatureLegacyTypes(t *testing.T) {
	legacyTypes := []struct {
		name    string
		sigType uint16
		keySize int
		sigSize int
	}{
		{"DSA_SHA1", signature.SIGNATURE_TYPE_DSA_SHA1, 128, signature.DSA_SHA1_SIZE},
		{"RSA_2048", signature.SIGNATURE_TYPE_RSA_SHA256_2048, 256, signature.RSA_SHA256_2048_SIZE},
		{"RSA_3072", signature.SIGNATURE_TYPE_RSA_SHA384_3072, 384, signature.RSA_SHA384_3072_SIZE},
		{"RSA_4096", signature.SIGNATURE_TYPE_RSA_SHA512_4096, 512, signature.RSA_SHA512_4096_SIZE},
	}

	for _, tc := range legacyTypes {
		t.Run(tc.name, func(t *testing.T) {
			key := make([]byte, tc.keySize)
			sig := make([]byte, tc.sigSize)
			offlineSig, err := NewOfflineSignature(
				uint32(time.Now().UTC().Add(24*time.Hour).Unix()),
				key_certificate.KEYCERT_SIGN_DSA_SHA1,
				make([]byte, key_certificate.KEYCERT_SIGN_DSA_SHA1_SIZE),
				sig,
				tc.sigType,
			)
			require.NoError(t, err)
			_, verr := offlineSig.VerifySignature(key)
			assert.Error(t, verr, "legacy type %d should return error", tc.sigType)
			assert.Contains(t, verr.Error(), "not implemented",
				"error for legacy type %d should mention 'not implemented'", tc.sigType)
		})
	}
}

// TestVerifySignatureECDSAInvalidKey confirms that ECDSA types return a meaningful
// error when the supplied public key is not a valid curve point (e.g. all-zero bytes).
func TestVerifySignatureECDSAInvalidKey(t *testing.T) {
	type ecdsaCase struct {
		name    string
		sigType uint16
		keySize int
		sigSize int
	}
	cases := []ecdsaCase{
		{"ECDSA_P256", signature.SIGNATURE_TYPE_ECDSA_SHA256_P256, 64, signature.ECDSA_SHA256_P256_SIZE},
		{"ECDSA_P384", signature.SIGNATURE_TYPE_ECDSA_SHA384_P384, 96, signature.ECDSA_SHA384_P384_SIZE},
		{"ECDSA_P521", signature.SIGNATURE_TYPE_ECDSA_SHA512_P521, 132, signature.ECDSA_SHA512_P521_SIZE},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sig := make([]byte, tc.sigSize)
			offlineSig, err := NewOfflineSignature(
				uint32(time.Now().UTC().Add(24*time.Hour).Unix()),
				key_certificate.KEYCERT_SIGN_DSA_SHA1,
				make([]byte, key_certificate.KEYCERT_SIGN_DSA_SHA1_SIZE),
				sig,
				tc.sigType,
			)
			require.NoError(t, err)
			// All-zero key bytes are not on any curve — expect an error.
			_, verr := offlineSig.VerifySignature(make([]byte, tc.keySize))
			assert.Error(t, verr, "ECDSA type %d with invalid key should return error", tc.sigType)
		})
	}
}

// TestCreateOfflineSignatureLegacyDestTypes confirms that DSA-SHA1 and RSA destination
// types return explicit errors when passed any signer (legacy algorithms unsupported).
func TestCreateOfflineSignatureLegacyDestTypes(t *testing.T) {
	_, privKey, _ := ed25519.GenerateKey(nil)
	transientKey := make([]byte, key_certificate.KEYCERT_SIGN_DSA_SHA1_SIZE)
	expires := uint32(time.Now().UTC().Add(24 * time.Hour).Unix())

	legacyTypes := []uint16{
		signature.SIGNATURE_TYPE_DSA_SHA1,
		signature.SIGNATURE_TYPE_RSA_SHA256_2048,
		signature.SIGNATURE_TYPE_RSA_SHA384_3072,
		signature.SIGNATURE_TYPE_RSA_SHA512_4096,
	}

	for _, destType := range legacyTypes {
		t.Run(fmt.Sprintf("legacy_dest_type_%d", destType), func(t *testing.T) {
			_, err := CreateOfflineSignature(
				expires,
				key_certificate.KEYCERT_SIGN_DSA_SHA1,
				transientKey,
				privKey,
				destType,
			)
			assert.Error(t, err, "legacy destination type %d should return error", destType)
			assert.Contains(t, err.Error(), "not implemented",
				"error for legacy type %d should mention 'not implemented'", destType)
		})
	}
}

// TestCreateOfflineSignatureECDSAWrongKey confirms that passing an ed25519.PrivateKey for
// an ECDSA destination type returns an error (wrong key type), not a silent corruption.
func TestCreateOfflineSignatureECDSAWrongKey(t *testing.T) {
	_, privKey, _ := ed25519.GenerateKey(nil)
	transientKey := make([]byte, key_certificate.KEYCERT_SIGN_DSA_SHA1_SIZE)
	expires := uint32(time.Now().UTC().Add(24 * time.Hour).Unix())

	for _, destType := range []uint16{
		signature.SIGNATURE_TYPE_ECDSA_SHA256_P256,
		signature.SIGNATURE_TYPE_ECDSA_SHA384_P384,
		signature.SIGNATURE_TYPE_ECDSA_SHA512_P521,
	} {
		t.Run(fmt.Sprintf("ecdsa_dest_type_%d_wrong_key", destType), func(t *testing.T) {
			_, err := CreateOfflineSignature(
				expires,
				key_certificate.KEYCERT_SIGN_DSA_SHA1,
				transientKey,
				privKey, // ed25519.PrivateKey — wrong type for ECDSA destination
				destType,
			)
			assert.Error(t, err, "ECDSA destination with ed25519 signer should fail")
		})
	}
}

// =========================================================================
// Ed25519ph is distinct from Ed25519 signing
// Verifies the SHA-512 pre-hashing produces different signatures
// =========================================================================

func TestEd25519phProducesDifferentSignature(t *testing.T) {
	_, privKey, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	expires := uint32(time.Now().UTC().Add(24 * time.Hour).Unix())
	transientKey := make([]byte, key_certificate.KEYCERT_SIGN_ED25519_SIZE)
	for i := range transientKey {
		transientKey[i] = byte(i + 1)
	}

	// Create with Ed25519 (type 7)
	ed25519Sig, err := CreateOfflineSignature(
		expires,
		key_certificate.KEYCERT_SIGN_ED25519,
		transientKey,
		privKey,
		signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519,
	)
	require.NoError(t, err)

	// Create with Ed25519ph (type 8) — same message, same key
	ed25519phSig, err := CreateOfflineSignature(
		expires,
		key_certificate.KEYCERT_SIGN_ED25519,
		transientKey,
		privKey,
		signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519PH,
	)
	require.NoError(t, err)

	assert.NotEqual(t, ed25519Sig.Signature(), ed25519phSig.Signature(),
		"Ed25519 and Ed25519ph should produce different signatures for the same message "+
			"(Ed25519ph applies SHA-512 pre-hashing)")
}

// =========================================================================
// Cross-verification must fail: Ed25519 signature must not verify as Ed25519ph
// =========================================================================

func TestEd25519AndEd25519phNotInterchangeable(t *testing.T) {
	pubKey, privKey, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	expires := uint32(time.Now().UTC().Add(24 * time.Hour).Unix())
	transientKey := make([]byte, key_certificate.KEYCERT_SIGN_ED25519_SIZE)

	// Create Ed25519 signature
	ed25519OffSig, err := CreateOfflineSignature(
		expires, key_certificate.KEYCERT_SIGN_ED25519, transientKey,
		privKey, signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519,
	)
	require.NoError(t, err)

	// Try to verify Ed25519 signature as Ed25519ph — must fail
	// Build a fake OfflineSignature with Ed25519ph dest type but Ed25519 signature bytes
	fakePhSig := OfflineSignature{
		expires:            ed25519OffSig.expires,
		sigtype:            ed25519OffSig.sigtype,
		transientPublicKey: ed25519OffSig.TransientPublicKey(),
		signature:          ed25519OffSig.Signature(),
		destinationSigType: signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519PH,
	}
	valid, err := fakePhSig.VerifySignature(pubKey)
	assert.NoError(t, err)
	assert.False(t, valid, "Ed25519 signature must not verify when treated as Ed25519ph")
}

// =========================================================================
// ECDSA end-to-end tests (AUDIT SPEC fix: ECDSA P256/P384/P521 now supported)
// =========================================================================

func TestCreateAndVerifyECDSAOfflineSignature(t *testing.T) {
	type ecdsaConfig struct {
		name           string
		curve          elliptic.Curve
		destSigType    uint16
		transientType  uint16
		transientKSize int
	}

	configs := []ecdsaConfig{
		{
			name:           "P256",
			curve:          elliptic.P256(),
			destSigType:    signature.SIGNATURE_TYPE_ECDSA_SHA256_P256,
			transientType:  key_certificate.KEYCERT_SIGN_ED25519,
			transientKSize: key_certificate.KEYCERT_SIGN_ED25519_SIZE,
		},
		{
			name:           "P384",
			curve:          elliptic.P384(),
			destSigType:    signature.SIGNATURE_TYPE_ECDSA_SHA384_P384,
			transientType:  key_certificate.KEYCERT_SIGN_ED25519,
			transientKSize: key_certificate.KEYCERT_SIGN_ED25519_SIZE,
		},
		{
			name:           "P521",
			curve:          elliptic.P521(),
			destSigType:    signature.SIGNATURE_TYPE_ECDSA_SHA512_P521,
			transientType:  key_certificate.KEYCERT_SIGN_ED25519,
			transientKSize: key_certificate.KEYCERT_SIGN_ED25519_SIZE,
		},
	}

	for _, cfg := range configs {
		t.Run(cfg.name, func(t *testing.T) {
			privKey, err := ecdsa.GenerateKey(cfg.curve, cryptorand.Reader)
			require.NoError(t, err)

			expires := uint32(time.Now().UTC().Add(24 * time.Hour).Unix())
			transientKey := make([]byte, cfg.transientKSize)
			for i := range transientKey {
				transientKey[i] = byte(i + 1)
			}

			offlineSig, err := CreateOfflineSignature(
				expires,
				cfg.transientType,
				transientKey,
				privKey,
				cfg.destSigType,
			)
			require.NoError(t, err, "CreateOfflineSignature should succeed for %s", cfg.name)

			// Extract raw uncompressed public key bytes: x || y, zero-padded to coordSize.
			coordSize := (cfg.curve.Params().BitSize + 7) / 8
			pubKeyBytes := make([]byte, 2*coordSize)
			xBytes := privKey.PublicKey.X.Bytes()
			yBytes := privKey.PublicKey.Y.Bytes()
			copy(pubKeyBytes[coordSize-len(xBytes):coordSize], xBytes)
			copy(pubKeyBytes[2*coordSize-len(yBytes):], yBytes)

			t.Run("valid_signature_verifies", func(t *testing.T) {
				valid, vErr := offlineSig.VerifySignature(pubKeyBytes)
				assert.NoError(t, vErr)
				assert.True(t, valid, "%s signature should verify with correct public key", cfg.name)
			})

			t.Run("wrong_public_key_fails", func(t *testing.T) {
				otherPriv, keyErr := ecdsa.GenerateKey(cfg.curve, cryptorand.Reader)
				require.NoError(t, keyErr)
				otherPub := make([]byte, 2*coordSize)
				ox := otherPriv.PublicKey.X.Bytes()
				oy := otherPriv.PublicKey.Y.Bytes()
				copy(otherPub[coordSize-len(ox):coordSize], ox)
				copy(otherPub[2*coordSize-len(oy):], oy)
				valid, vErr := offlineSig.VerifySignature(otherPub)
				assert.NoError(t, vErr)
				assert.False(t, valid, "%s signature should not verify with wrong public key", cfg.name)
			})

			t.Run("round_trip_serialization", func(t *testing.T) {
				serialized := offlineSig.Bytes()
				parsed, rem, pErr := ReadOfflineSignature(serialized, cfg.destSigType)
				require.NoError(t, pErr)
				assert.Empty(t, rem)
				valid, vErr := parsed.VerifySignature(pubKeyBytes)
				assert.NoError(t, vErr)
				assert.True(t, valid, "%s round-tripped signature should still verify", cfg.name)
			})
		})
	}
}

// TestNewOfflineSignatureZeroExpiresRejected verifies the AUDIT BUG fix:
// NewOfflineSignature must reject expires==0 instead of returning a poisoned object.
func TestNewOfflineSignatureZeroExpiresRejected(t *testing.T) {
	transientKey := make([]byte, key_certificate.KEYCERT_SIGN_ED25519_SIZE)
	sig := make([]byte, signature.EdDSA_SHA512_Ed25519_SIZE)

	_, err := NewOfflineSignature(
		0,
		key_certificate.KEYCERT_SIGN_ED25519,
		transientKey, sig,
		signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519,
	)
	require.Error(t, err, "NewOfflineSignature(expires=0) must return an error")
	assert.Contains(t, err.Error(), "non-zero",
		"error message should direct callers toward the valid range")
}
