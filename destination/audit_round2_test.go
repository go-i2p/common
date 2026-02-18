package destination

import (
	"crypto/rand"
	"encoding/binary"
	"testing"

	"github.com/go-i2p/common/key_certificate"
	"github.com/go-i2p/common/keys_and_cert"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============================================================
// [SPEC] Prohibited signing key types rejected for Destinations
// ============================================================

func TestAudit2_ProhibitedSigningTypesRejected(t *testing.T) {
	prohibitedTypes := []struct {
		name    string
		sigType int
	}{
		{"RSA_SHA256_2048", key_certificate.KEYCERT_SIGN_RSA2048},
		{"RSA_SHA384_3072", key_certificate.KEYCERT_SIGN_RSA3072},
		{"RSA_SHA512_4096", key_certificate.KEYCERT_SIGN_RSA4096},
		{"Ed25519ph", key_certificate.KEYCERT_SIGN_ED25519PH},
	}

	for _, tc := range prohibitedTypes {
		t.Run(tc.name+"_via_ReadDestination", func(t *testing.T) {
			data := createDestinationBytesWithSigningType(t, tc.sigType)
			_, _, err := ReadDestination(data)
			// RSA types are rejected either by keys_and_cert (excess key size)
			// or by destination's validateDestinationKeyTypes.
			// Either way, an error must be returned.
			require.Error(t, err,
				"ReadDestination should reject prohibited signing type %d (%s)",
				tc.sigType, tc.name)
		})

		t.Run(tc.name+"_via_validateDestinationSigningType", func(t *testing.T) {
			kac := buildKACWithSigningType(t, tc.sigType)
			if kac == nil {
				t.Skipf("cannot construct KeyCertificate with signing type %d", tc.sigType)
			}
			err := validateDestinationKeyTypes(kac)
			require.Error(t, err,
				"validateDestinationKeyTypes should reject signing type %d (%s)",
				tc.sigType, tc.name)
			assert.Contains(t, err.Error(), "not permitted for Destinations")
		})
	}
}

func TestAudit2_AllowedSigningTypesAccepted(t *testing.T) {
	// Only test signing types whose keys fit in the 128-byte inline space.
	// ECDSA_P521 (132 bytes) requires excess key reconstruction in keys_and_cert,
	// which is not yet implemented — tested separately.
	allowedTypes := []struct {
		name    string
		sigType int
	}{
		{"DSA_SHA1", key_certificate.KEYCERT_SIGN_DSA_SHA1},
		{"ECDSA_P256", key_certificate.KEYCERT_SIGN_P256},
		{"ECDSA_P384", key_certificate.KEYCERT_SIGN_P384},
		{"Ed25519", key_certificate.KEYCERT_SIGN_ED25519},
		{"RedDSA_Ed25519", key_certificate.KEYCERT_SIGN_REDDSA_ED25519},
	}

	for _, tc := range allowedTypes {
		t.Run(tc.name+"_via_ReadDestination", func(t *testing.T) {
			data := createDestinationBytesWithSigningType(t, tc.sigType)
			dest, _, err := ReadDestination(data)
			require.NoError(t, err,
				"ReadDestination should accept signing type %d (%s)",
				tc.sigType, tc.name)
			assert.NotNil(t, dest.KeysAndCert)
		})
	}
}

func TestAudit2_ValidateDestinationSigningTypeDirect(t *testing.T) {
	t.Run("RSA types rejected", func(t *testing.T) {
		for _, st := range []int{
			key_certificate.KEYCERT_SIGN_RSA2048,
			key_certificate.KEYCERT_SIGN_RSA3072,
			key_certificate.KEYCERT_SIGN_RSA4096,
		} {
			kac := buildKACWithSigningType(t, st)
			if kac == nil {
				continue
			}
			err := validateDestinationKeyTypes(kac)
			require.Error(t, err, "signing type %d should be rejected", st)
			assert.Contains(t, err.Error(), "RSA")
		}
	})

	t.Run("Ed25519ph rejected", func(t *testing.T) {
		kac := buildKACWithSigningType(t, key_certificate.KEYCERT_SIGN_ED25519PH)
		if kac == nil {
			t.Skip("cannot construct KeyCertificate with Ed25519ph")
		}
		err := validateDestinationKeyTypes(kac)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "Ed25519ph")
	})

	t.Run("Ed25519 allowed", func(t *testing.T) {
		kac := buildKACWithSigningType(t, key_certificate.KEYCERT_SIGN_ED25519)
		if kac == nil {
			t.Skip("cannot construct KeyCertificate with Ed25519")
		}
		err := validateDestinationKeyTypes(kac)
		assert.NoError(t, err)
	})
}

// ============================================================
// [TEST] Ed25519/X25519 key type Destinations
// ============================================================

func TestAudit2_Ed25519X25519Destination(t *testing.T) {
	t.Run("construct and round-trip Ed25519/X25519 destination", func(t *testing.T) {
		data := createEd25519X25519DestinationBytes(t)

		// Parse
		dest, remainder, err := ReadDestination(data)
		require.NoError(t, err)
		assert.Empty(t, remainder)
		assert.NotNil(t, dest.KeysAndCert)

		// Verify key types
		require.NotNil(t, dest.KeyCertificate)
		assert.Equal(t, key_certificate.KEYCERT_SIGN_ED25519,
			dest.KeyCertificate.SigningPublicKeyType())
		assert.Equal(t, key_certificate.KEYCERT_CRYPTO_X25519,
			dest.KeyCertificate.PublicKeyType())

		// Serialize and re-parse
		serialized, err := dest.Bytes()
		require.NoError(t, err)
		assert.Equal(t, data, serialized)

		dest2, _, err := ReadDestination(serialized)
		require.NoError(t, err)

		// Same addresses
		addr1, err := dest.Base32Address()
		require.NoError(t, err)
		addr2, err := dest2.Base32Address()
		require.NoError(t, err)
		assert.Equal(t, addr1, addr2)

		b64_1, err := dest.Base64()
		require.NoError(t, err)
		b64_2, err := dest2.Base64()
		require.NoError(t, err)
		assert.Equal(t, b64_1, b64_2)
	})

	t.Run("via NewDestination", func(t *testing.T) {
		data := createEd25519X25519DestinationBytes(t)
		kac, _, err := keys_and_cert.ReadKeysAndCert(data)
		require.NoError(t, err)

		dest, err := NewDestination(kac)
		require.NoError(t, err)
		assert.True(t, dest.IsValid())

		require.NotNil(t, dest.KeyCertificate)
		assert.Equal(t, key_certificate.KEYCERT_SIGN_ED25519,
			dest.KeyCertificate.SigningPublicKeyType())
		assert.Equal(t, key_certificate.KEYCERT_CRYPTO_X25519,
			dest.KeyCertificate.PublicKeyType())
	})

	t.Run("via NewDestinationFromBytes", func(t *testing.T) {
		data := createEd25519X25519DestinationBytes(t)
		dest, remainder, err := NewDestinationFromBytes(data)
		require.NoError(t, err)
		require.NotNil(t, dest)
		assert.Empty(t, remainder)
		assert.True(t, dest.IsValid())
	})
}

// ============================================================
// [TEST] Destination with excess key data in certificate
// ============================================================

func TestAudit2_ExcessKeyDataInCertificate(t *testing.T) {
	t.Run("ECDSA_P256 signing key with excess data", func(t *testing.T) {
		// ECDSA_P256 signing public key is 64 bytes.
		// Default signing key space is 128 bytes.
		// Since 64 < 128, there are 64 bytes of padding, no excess.
		// But let's verify parsing works correctly.
		data := createDestinationBytesWithSigningType(t, key_certificate.KEYCERT_SIGN_P256)
		dest, _, err := ReadDestination(data)
		require.NoError(t, err)
		assert.NotNil(t, dest.KeysAndCert)
	})

	t.Run("ECDSA_P521 signing key with excess data", func(t *testing.T) {
		// ECDSA_P521 signing public key is 132 bytes.
		// Default signing key space is 128 bytes.
		// Excess = 132 - 128 = 4 bytes stored in certificate.
		// NOTE: The keys_and_cert package does not yet support excess key
		// reconstruction, so parsing fails. This test documents the limitation.
		data := createDestinationBytesWithExcessSigningKey(t,
			key_certificate.KEYCERT_SIGN_P521, 4)
		_, _, err := ReadDestination(data)
		// Expected to fail until keys_and_cert supports excess key reconstruction
		assert.Error(t, err, "excess key data reconstruction not yet implemented in keys_and_cert")
	})
}

// ============================================================
// [TEST] Fuzz test coverage for Destination address generation
// ============================================================

func FuzzDestinationParse(f *testing.F) {
	// Seed with valid destination bytes
	validData := make([]byte, 391)
	for i := range validData {
		validData[i] = byte(i % 256)
	}
	validData[384] = 0x05
	validData[385] = 0x00
	validData[386] = 0x04
	validData[387] = 0x00
	validData[388] = 0x00
	validData[389] = 0x00
	validData[390] = 0x00

	f.Add(validData)
	f.Add([]byte{})
	f.Add([]byte{0x00})

	f.Fuzz(func(t *testing.T, data []byte) {
		dest, _, err := ReadDestination(data)
		if err != nil {
			return
		}
		// If parse succeeds, Bytes() should not panic
		b, err := dest.Bytes()
		if err != nil {
			return
		}
		// Re-parse should succeed
		dest2, _, err := ReadDestination(b)
		if err != nil {
			t.Fatalf("round-trip failed: parsed OK, serialized OK, but re-parse failed: %v", err)
		}

		// Base32Address and Base64 should not panic
		_, _ = dest2.Base32Address()
		_, _ = dest2.Base64()
	})
}

// ============================================================
// [QUALITY] I2PBase32Suffix constant naming
// ============================================================

func TestAudit2_I2PBase32SuffixConstant(t *testing.T) {
	// Verify both constant names refer to the same value
	assert.Equal(t, I2PBase32Suffix, I2P_BASE32_SUFFIX,
		"Both constant names should have the same value")
	assert.Equal(t, ".b32.i2p", I2PBase32Suffix)
}

// ============================================================
// [GAP] Pointer receiver consistency
// ============================================================

func TestAudit2_PointerReceiverConsistency(t *testing.T) {
	t.Run("pointer receiver methods work on value from ReadDestination", func(t *testing.T) {
		data := createValidDestinationBytes(t)
		dest, _, err := ReadDestination(data)
		require.NoError(t, err)

		// All methods should work on the addressable value
		assert.NoError(t, dest.Validate())
		assert.True(t, dest.IsValid())

		_, err = dest.Bytes()
		assert.NoError(t, err)

		_, err = dest.Base32Address()
		assert.NoError(t, err)

		_, err = dest.Base64()
		assert.NoError(t, err)

		_, err = dest.Hash()
		assert.NoError(t, err)

		assert.True(t, (&dest).Equals(&dest))
	})

	t.Run("nil receiver safety for pointer methods", func(t *testing.T) {
		var dest *Destination

		err := dest.Validate()
		assert.Error(t, err)

		assert.False(t, dest.IsValid())

		_, err = dest.Hash()
		assert.Error(t, err)
	})

	t.Run("nil KeysAndCert safety for value methods", func(t *testing.T) {
		dest := Destination{KeysAndCert: nil}

		_, err := dest.Bytes()
		assert.Error(t, err)

		_, err = dest.Base32Address()
		assert.Error(t, err)

		_, err = dest.Base64()
		assert.Error(t, err)
	})
}

// ============================================================
// [QUALITY] Base32Address no longer logs the full address
// ============================================================

func TestAudit2_Base32AddressDoesNotLeakInLog(t *testing.T) {
	// This is a code review finding; we just verify the method works
	// without logging the full address (verified by code inspection).
	data := createValidDestinationBytes(t)
	dest, _, err := ReadDestination(data)
	require.NoError(t, err)

	addr, err := dest.Base32Address()
	require.NoError(t, err)
	assert.Contains(t, addr, ".b32.i2p")
}

// ============================================================
// Test Helpers
// ============================================================

// createDestinationBytesWithSigningType creates valid destination bytes with
// a specific signing type and ElGamal crypto type.
func createDestinationBytesWithSigningType(t *testing.T, sigType int) []byte {
	t.Helper()

	keysData := make([]byte, 384)
	for i := range keysData {
		keysData[i] = byte(i % 256)
	}

	// I2P spec wire format: sig_type first, then crypto_type
	sigBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(sigBytes, uint16(sigType))

	certData := []byte{
		0x05,       // type = KEY certificate (5)
		0x00, 0x04, // length = 4 bytes
		sigBytes[0], sigBytes[1], // sig_type [first per spec]
		0x00, 0x00, // crypto_type = 0 (ElGamal) [second per spec]
	}

	return append(keysData, certData...)
}

// createEd25519X25519DestinationBytes creates valid destination bytes with
// Ed25519 signing (type 7) and X25519 encryption (type 4).
// This is the recommended modern key combination.
func createEd25519X25519DestinationBytes(t *testing.T) []byte {
	t.Helper()

	// Ed25519 signing public key: 32 bytes (at end of 128-byte signing key space)
	// X25519 crypto public key: 32 bytes (at end of 256-byte public key space)
	// Both fit within the 384-byte KeysAndCert data, with padding.
	keysData := make([]byte, 384)
	_, err := rand.Read(keysData)
	require.NoError(t, err)

	// Key certificate payload for Ed25519/X25519:
	// sig_type = 7 (Ed25519), crypto_type = 4 (X25519)
	certData := []byte{
		0x05,       // type = KEY certificate (5)
		0x00, 0x04, // length = 4 bytes
		0x00, 0x07, // sig_type = 7 (Ed25519) [first per spec]
		0x00, 0x04, // crypto_type = 4 (X25519) [second per spec]
	}

	return append(keysData, certData...)
}

// createDestinationBytesWithExcessSigningKey creates destination bytes
// where the signing public key exceeds the 128-byte default space,
// with the excess stored in the Key Certificate payload.
func createDestinationBytesWithExcessSigningKey(t *testing.T, sigType int, excessBytes int) []byte {
	t.Helper()

	keysData := make([]byte, 384)
	_, err := rand.Read(keysData)
	require.NoError(t, err)

	sigBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(sigBytes, uint16(sigType))

	// Payload: sig_type (2) + crypto_type (2) + excess signing key data
	payloadLen := 4 + excessBytes
	excessData := make([]byte, excessBytes)
	_, _ = rand.Read(excessData)

	lenBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBytes, uint16(payloadLen))

	certData := []byte{0x05, lenBytes[0], lenBytes[1]}
	certData = append(certData, sigBytes[0], sigBytes[1])
	certData = append(certData, 0x00, 0x00) // crypto_type = ElGamal
	certData = append(certData, excessData...)

	return append(keysData, certData...)
}

// buildKACWithSigningType creates a KeysAndCert with the given signing type
// for direct validation testing.
func buildKACWithSigningType(t *testing.T, sigType int) *keys_and_cert.KeysAndCert {
	t.Helper()
	keyCert, err := key_certificate.NewKeyCertificateWithTypes(
		sigType,
		key_certificate.KEYCERT_CRYPTO_ELG,
	)
	if err != nil {
		t.Logf("cannot construct KeyCertificate with signing type %d: %v", sigType, err)
		return nil
	}
	return &keys_and_cert.KeysAndCert{KeyCertificate: keyCert}
}
