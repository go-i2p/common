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
