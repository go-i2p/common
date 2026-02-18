package destination

import (
	"regexp"
	"testing"

	"github.com/go-i2p/common/key_certificate"
	"github.com/go-i2p/common/keys_and_cert"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

//
// Finding 1 [BUG]: ReadDestination returns zero Destination on error
//

func TestAudit_ReadDestinationReturnsZeroOnError(t *testing.T) {
	t.Run("short data returns error and zero Destination", func(t *testing.T) {
		dest, _, err := ReadDestination([]byte{0x00, 0x01, 0x02})
		require.Error(t, err)
		assert.Nil(t, dest.KeysAndCert, "Destination should have nil KeysAndCert on error")
	})

	t.Run("empty data returns error and zero Destination", func(t *testing.T) {
		dest, _, err := ReadDestination([]byte{})
		require.Error(t, err)
		assert.Nil(t, dest.KeysAndCert, "Destination should have nil KeysAndCert on error")
	})

	t.Run("nil data returns error and zero Destination", func(t *testing.T) {
		dest, _, err := ReadDestination(nil)
		require.Error(t, err)
		assert.Nil(t, dest.KeysAndCert, "Destination should have nil KeysAndCert on error")
	})
}

//
// Finding 2 [BUG]: Bytes(), Base32Address(), Base64() return error on nil KeysAndCert
//

func TestAudit_BytesNilKeysAndCert(t *testing.T) {
	dest := Destination{KeysAndCert: nil}
	_, err := dest.Bytes()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not initialized")
}

func TestAudit_Base32AddressNilKeysAndCert(t *testing.T) {
	dest := Destination{KeysAndCert: nil}
	_, err := dest.Base32Address()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not initialized")
}

func TestAudit_Base64NilKeysAndCert(t *testing.T) {
	dest := Destination{KeysAndCert: nil}
	_, err := dest.Base64()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not initialized")
}

//
// Finding 4 [SPEC]: Base32Address uses TrimRight (was Trim)
//

func TestAudit_Base32AddressFormat(t *testing.T) {
	destBytes := createValidDestinationBytes(t)
	dest, _, err := ReadDestination(destBytes)
	require.NoError(t, err)

	addr, err := dest.Base32Address()
	require.NoError(t, err)

	// I2P base32 address: 52 lowercase base32 characters + ".b32.i2p"
	// SHA-256 output is 32 bytes → base32 encodes to 52 chars (no padding)
	pattern := regexp.MustCompile(`^[a-z2-7]{52}\.b32\.i2p$`)
	assert.Regexp(t, pattern, addr,
		"Base32 address should be 52 lowercase base32 chars followed by .b32.i2p")
	assert.Len(t, addr, 60, "Base32 address should be exactly 60 characters")
}

//
// Finding 5 [SPEC]: Prohibited crypto types rejected
//

func TestAudit_ProhibitedCryptoTypesRejected(t *testing.T) {
	prohibitedTypes := []struct {
		name       string
		cryptoType int
	}{
		{"MLKEM512_X25519", key_certificate.KEYCERT_CRYPTO_MLKEM512_X25519},
		{"MLKEM768_X25519", key_certificate.KEYCERT_CRYPTO_MLKEM768_X25519},
		{"MLKEM1024_X25519", key_certificate.KEYCERT_CRYPTO_MLKEM1024_X25519},
	}

	for _, tc := range prohibitedTypes {
		t.Run(tc.name+"_via_ReadDestination", func(t *testing.T) {
			data := createDestinationBytesWithCryptoType(t, tc.cryptoType)
			_, _, err := ReadDestination(data)
			require.Error(t, err,
				"ReadDestination should reject prohibited crypto type %d (%s)",
				tc.cryptoType, tc.name)
		})
	}
}

func TestAudit_AllowedCryptoTypesAccepted(t *testing.T) {
	allowedTypes := []struct {
		name       string
		cryptoType int
	}{
		{"ElGamal", key_certificate.KEYCERT_CRYPTO_ELG},
		{"X25519", key_certificate.KEYCERT_CRYPTO_X25519},
	}

	for _, tc := range allowedTypes {
		t.Run(tc.name+"_via_ReadDestination", func(t *testing.T) {
			data := createDestinationBytesWithCryptoType(t, tc.cryptoType)
			dest, _, err := ReadDestination(data)
			require.NoError(t, err)
			assert.NotNil(t, dest.KeysAndCert)
		})
	}
}

func TestAudit_ValidateDestinationKeyTypesDirect(t *testing.T) {
	t.Run("nil KeysAndCert passes", func(t *testing.T) {
		err := validateDestinationKeyTypes(nil)
		assert.NoError(t, err)
	})

	t.Run("MLKEM types rejected", func(t *testing.T) {
		for _, ct := range []int{
			key_certificate.KEYCERT_CRYPTO_MLKEM512_X25519,
			key_certificate.KEYCERT_CRYPTO_MLKEM768_X25519,
			key_certificate.KEYCERT_CRYPTO_MLKEM1024_X25519,
		} {
			// Build a KeyCertificate with the given crypto type
			keyCert, err := key_certificate.NewKeyCertificateWithTypes(
				key_certificate.KEYCERT_SIGN_DSA_SHA1,
				ct,
			)
			if err != nil {
				// Some key types may not be constructible, skip
				t.Skipf("cannot construct KeyCertificate with crypto type %d: %v", ct, err)
			}
			kac := &keys_and_cert.KeysAndCert{KeyCertificate: keyCert}
			err = validateDestinationKeyTypes(kac)
			require.Error(t, err, "crypto type %d should be rejected", ct)
			assert.Contains(t, err.Error(), "not permitted for Destinations")
		}
	})
}

//
// Finding 6 [GAP]: Hash() method
//

func TestAudit_HashMethod(t *testing.T) {
	t.Run("valid destination returns consistent hash", func(t *testing.T) {
		destBytes := createValidDestinationBytes(t)
		dest, _, err := ReadDestination(destBytes)
		require.NoError(t, err)

		hash1, err := (&dest).Hash()
		require.NoError(t, err)
		hash2, err := (&dest).Hash()
		require.NoError(t, err)

		assert.Equal(t, hash1, hash2, "Same destination should produce same hash")
		assert.NotEqual(t, [32]byte{}, hash1, "Hash should not be zero")
	})

	t.Run("nil destination returns error", func(t *testing.T) {
		var dest *Destination
		_, err := dest.Hash()
		require.Error(t, err)
	})

	t.Run("destination with nil KeysAndCert returns error", func(t *testing.T) {
		dest := &Destination{KeysAndCert: nil}
		_, err := dest.Hash()
		require.Error(t, err)
	})
}

//
// Finding 7 [GAP]: Equals() method
//

func TestAudit_EqualsMethod(t *testing.T) {
	t.Run("same destination equals itself", func(t *testing.T) {
		destBytes := createValidDestinationBytes(t)
		dest, _, err := ReadDestination(destBytes)
		require.NoError(t, err)
		destPtr := &dest

		assert.True(t, destPtr.Equals(destPtr))
	})

	t.Run("identical destinations are equal", func(t *testing.T) {
		destBytes := createValidDestinationBytes(t)
		dest1, _, err := ReadDestination(destBytes)
		require.NoError(t, err)
		dest2, _, err := ReadDestination(destBytes)
		require.NoError(t, err)

		assert.True(t, (&dest1).Equals(&dest2))
	})

	t.Run("nil destination not equal", func(t *testing.T) {
		destBytes := createValidDestinationBytes(t)
		dest, _, err := ReadDestination(destBytes)
		require.NoError(t, err)

		assert.False(t, (&dest).Equals(nil))
	})

	t.Run("nil receiver not equal", func(t *testing.T) {
		var dest *Destination
		other := &Destination{}
		assert.False(t, dest.Equals(other))
	})

	t.Run("destination with nil KeysAndCert not equal", func(t *testing.T) {
		dest1 := &Destination{KeysAndCert: nil}
		dest2 := &Destination{KeysAndCert: nil}
		assert.False(t, dest1.Equals(dest2))
	})
}

//
// Finding 8 [GAP]: ReadDestination no longer logs success on error
// (Verified by the code change; this test ensures error path doesn't panic)
//

func TestAudit_ReadDestinationErrorDoesNotPanic(t *testing.T) {
	// 387 bytes with invalid certificate type
	invalidData := make([]byte, keys_and_cert.KEYS_AND_CERT_MIN_SIZE)
	for i := range invalidData {
		invalidData[i] = byte(i % 256)
	}
	// Set certificate type to an invalid value
	invalidData[384] = 0xFF
	invalidData[385] = 0x00
	invalidData[386] = 0x00

	// Should not panic
	_, _, err := ReadDestination(invalidData)
	// We expect an error since the certificate type is invalid
	_ = err
}

//
// Finding 12 [TEST]: Negative test with KEYS_AND_CERT_MIN_SIZE bytes + invalid cert
//

func TestAudit_ReadDestinationInvalidCertType(t *testing.T) {
	data := make([]byte, keys_and_cert.KEYS_AND_CERT_MIN_SIZE)
	for i := range data {
		data[i] = byte(i % 256)
	}
	// Set certificate type to 0xFF (invalid)
	data[384] = 0xFF
	data[385] = 0x00
	data[386] = 0x00

	_, _, err := ReadDestination(data)
	require.Error(t, err, "ReadDestination should propagate error for invalid certificate type")
}

//
// Test helpers for audit tests
//

// createDestinationBytesWithCryptoType creates valid destination bytes with a specific crypto type.
func createDestinationBytesWithCryptoType(t *testing.T, cryptoType int) []byte {
	t.Helper()

	// Create minimal valid keys data (384 bytes)
	keysData := make([]byte, 384)
	for i := range keysData {
		keysData[i] = byte(i % 256)
	}

	// Create KEY certificate (type=5) with specified crypto type
	// KeyCertificate payload: sig_type (2 bytes) + crypto_type (2 bytes)
	certData := []byte{
		0x05,       // type = KEY certificate (5)
		0x00, 0x04, // length = 4 bytes
		0x00, 0x00, // sig_type = 0 (DSA-SHA1)
		byte(cryptoType >> 8), byte(cryptoType), // crypto_type
	}

	return append(keysData, certData...)
}
