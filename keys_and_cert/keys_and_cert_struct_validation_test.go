package keys_and_cert

import (
	"encoding/binary"
	"testing"

	"github.com/go-i2p/common/certificate"
	"github.com/go-i2p/common/key_certificate"
	"github.com/go-i2p/crypto/curve25519"
	"github.com/go-i2p/crypto/rand"
	"github.com/go-i2p/crypto/types"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============================================================================
// Validate()
// ============================================================================

func TestValidate(t *testing.T) {
	assert := assert.New(t)

	t.Run("nil struct", func(t *testing.T) {
		var kac *KeysAndCert
		err := kac.Validate()
		assert.NotNil(err)
		assert.Contains(err.Error(), "KeysAndCert is nil")
	})

	t.Run("missing key certificate", func(t *testing.T) {
		kac := &KeysAndCert{
			KeyCertificate:  nil,
			ReceivingPublic: createDummyReceivingKey(),
			SigningPublic:   createDummySigningKey(),
		}
		err := kac.Validate()
		assert.NotNil(err)
		assert.Contains(err.Error(), "KeyCertificate is required")
	})

	t.Run("missing receiving public key", func(t *testing.T) {
		kac := &KeysAndCert{
			KeyCertificate:  createDummyKeyCertificate(t),
			ReceivingPublic: nil,
			SigningPublic:   createDummySigningKey(),
		}
		err := kac.Validate()
		assert.NotNil(err)
		assert.Contains(err.Error(), "ReceivingPublic key is required")
	})

	t.Run("missing signing public key", func(t *testing.T) {
		kac := &KeysAndCert{
			KeyCertificate:  createDummyKeyCertificate(t),
			ReceivingPublic: createDummyReceivingKey(),
			SigningPublic:   nil,
		}
		err := kac.Validate()
		assert.NotNil(err)
		assert.Contains(err.Error(), "SigningPublic key is required")
	})

	t.Run("valid struct", func(t *testing.T) {
		kac := createValidKeyAndCert(t)
		err := kac.Validate()
		assert.Nil(err)
	})
}

func TestValidateKeySizeMismatch(t *testing.T) {
	t.Run("wrong signing key size", func(t *testing.T) {
		keyCert := buildTestKeyCert(t, key_certificate.KEYCERT_SIGN_ED25519, key_certificate.KEYCERT_CRYPTO_ELG)
		kac := &KeysAndCert{
			KeyCertificate:  keyCert,
			ReceivingPublic: createDummyReceivingKey(),
			SigningPublic:   createWrongSizeSigningKey(),
		}
		err := kac.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "SigningPublic key size mismatch")
	})

	t.Run("correct sizes pass validation", func(t *testing.T) {
		kac := createValidKeyAndCert(t)
		err := kac.Validate()
		require.NoError(t, err)
	})
}

// ============================================================================
// IsValid()
// ============================================================================

func TestIsValid(t *testing.T) {
	assert := assert.New(t)

	t.Run("nil struct returns false", func(t *testing.T) {
		var kac *KeysAndCert
		assert.False(kac.IsValid())
	})

	t.Run("partial struct returns false", func(t *testing.T) {
		kac := &KeysAndCert{
			KeyCertificate: createDummyKeyCertificate(t),
		}
		assert.False(kac.IsValid())
	})

	t.Run("valid struct returns true", func(t *testing.T) {
		kac := createValidKeyAndCert(t)
		assert.True(kac.IsValid())
	})
}

// ============================================================================
// Zero-value safety
// ============================================================================

func TestZeroValueKeysAndCertUnsafe(t *testing.T) {
	assert := assert.New(t)

	var kac KeysAndCert
	assert.False(kac.IsValid())

	_, err := kac.Bytes()
	assert.NotNil(err)
	assert.Contains(err.Error(), "KeyCertificate is required")
}

// ============================================================================
// Bytes() error paths
// ============================================================================

func TestBytesWithInvalidStruct(t *testing.T) {
	assert := assert.New(t)

	t.Run("nil key certificate", func(t *testing.T) {
		kac := &KeysAndCert{
			ReceivingPublic: createDummyReceivingKey(),
			SigningPublic:   createDummySigningKey(),
		}
		_, err := kac.Bytes()
		assert.NotNil(err)
		assert.Contains(err.Error(), "KeyCertificate is required")
	})

	t.Run("nil receiving key", func(t *testing.T) {
		kac := &KeysAndCert{
			KeyCertificate: createDummyKeyCertificate(t),
			SigningPublic:  createDummySigningKey(),
		}
		_, err := kac.Bytes()
		assert.NotNil(err)
		assert.Contains(err.Error(), "ReceivingPublic key is required")
	})
}

// ============================================================================
// ReadKeysAndCert error returns
// ============================================================================

func TestReadKeysAndCertReturnsNilOnError(t *testing.T) {
	assert := assert.New(t)

	t.Run("returns nil on insufficient data", func(t *testing.T) {
		d := make([]byte, 10)
		kac, _, err := ReadKeysAndCert(d)
		assert.NotNil(err)
		assert.Nil(kac)
	})

	t.Run("returns nil on certificate parse error", func(t *testing.T) {
		d := make([]byte, KEYS_AND_CERT_DATA_SIZE+3)
		d[KEYS_AND_CERT_DATA_SIZE] = 0xFF
		kac, _, err := ReadKeysAndCert(d)
		assert.NotNil(err)
		assert.Nil(kac)
	})
}

func TestNewKeysAndCertWithMissingData(t *testing.T) {
	assert := assert.New(t)

	cert_data := make([]byte, 128)
	_, remainder, err := ReadKeysAndCert(cert_data)
	assert.Equal(0, len(remainder))
	if assert.NotNil(err) {
		assert.Equal("error parsing KeysAndCert: data is smaller than minimum valid size", err.Error())
	}
}

// ============================================================================
// PublicKey / SigningPublicKey with bad data
// ============================================================================

func TestPublicKeyWithBadData(t *testing.T) {
	assert := assert.New(t)

	cert_data := []byte{0x05, 0x00, 0x04, 0x00, 0x01, 0x00, 0x00}
	pub_key_data := make([]byte, 193)
	d := make([]byte, 128)
	d = append(d, pub_key_data...)
	d = append(d, cert_data...)
	keys_and_cert, _, err := ReadKeysAndCert(d)

	pub_key, pub_key_err := keys_and_cert.PublicKey()
	if assert.NotNil(err) {
		assert.Equal("error parsing KeysAndCert: data is smaller than minimum valid size", err.Error())
	}
	assert.NotNil(pub_key_err)
	assert.Nil(pub_key)
}

func TestPublicKeyWithBadCertificate(t *testing.T) {
	assert := assert.New(t)
	cert_data := []byte{0x05, 0x00, 0x04, 0x00, 0x01}
	pub_key_data := make([]byte, 256)
	d := make([]byte, 128)
	d = append(d, pub_key_data...)
	d = append(d, cert_data...)
	keys_and_cert, _, err := ReadKeysAndCert(d)

	if assert.NotNil(err) {
		log.WithError(err).Debug("Correctly got error")
	}
	pub_key, pub_key_err := keys_and_cert.PublicKey()
	assert.NotNil(pub_key_err)
	assert.Nil(pub_key)
}

func TestSigningPublicKeyWithBadData(t *testing.T) {
	assert := assert.New(t)

	cert_data := []byte{0x05, 0x00, 0x04, 0x00, 0x01, 0x00, 0x00}
	pub_key_data := make([]byte, 256)
	d := make([]byte, 93)
	d = append(d, pub_key_data...)
	d = append(d, cert_data...)
	keys_and_cert, _, err := ReadKeysAndCert(d)

	signing_pub_key, signing_key_err := keys_and_cert.SigningPublicKey()
	assert.NotNil(err)
	assert.NotNil(signing_key_err)
	assert.Nil(signing_pub_key)
}

func TestSigningPublicKeyWithBadCertificate(t *testing.T) {
	assert := assert.New(t)

	cert_data := []byte{0x05, 0x00, 0x04, 0x00, 0x01}
	pub_key_data := make([]byte, 256)
	d := make([]byte, 128)
	d = append(d, pub_key_data...)
	d = append(d, cert_data...)
	keys_and_cert, _, err := ReadKeysAndCert(d)
	signing_pub_key, signing_key_err := keys_and_cert.SigningPublicKey()
	assert.NotNil(err)
	assert.NotNil(signing_key_err)
	assert.Nil(signing_pub_key)
}

// ============================================================================
// RSA signing types return error not panic
// ============================================================================

func TestReadKeysAndCert_RSASigningTypes(t *testing.T) {
	rsaTypes := []struct {
		name    string
		sigType int
	}{
		{"RSA2048", key_certificate.KEYCERT_SIGN_RSA2048},
		{"RSA3072", key_certificate.KEYCERT_SIGN_RSA3072},
		{"RSA4096", key_certificate.KEYCERT_SIGN_RSA4096},
	}
	for _, tt := range rsaTypes {
		t.Run(tt.name+"_does_not_panic", func(t *testing.T) {
			block := make([]byte, KEYS_AND_CERT_DATA_SIZE)
			certPayload := buildKeyCertPayload(tt.sigType, key_certificate.KEYCERT_CRYPTO_ELG)
			certBytes := []byte{certificate.CERT_KEY}
			lenBytes := make([]byte, 2)
			binary.BigEndian.PutUint16(lenBytes, uint16(len(certPayload)))
			certBytes = append(certBytes, lenBytes...)
			certBytes = append(certBytes, certPayload...)
			wireData := append(block, certBytes...)

			_, _, err := ReadKeysAndCert(wireData)
			require.Error(t, err)
		})
	}
}

// ============================================================================
// Malformed certificate data
// ============================================================================

func TestReadKeysAndCert_MalformedCertData(t *testing.T) {
	t.Run("zero-length KEY cert payload", func(t *testing.T) {
		block := make([]byte, KEYS_AND_CERT_DATA_SIZE)
		certBytes := []byte{certificate.CERT_KEY, 0x00, 0x00}
		wireData := append(block, certBytes...)
		_, _, err := ReadKeysAndCert(wireData)
		require.Error(t, err)
	})

	t.Run("HASHCASH cert type", func(t *testing.T) {
		block := make([]byte, KEYS_AND_CERT_DATA_SIZE)
		certBytes := []byte{0x01, 0x00, 0x00}
		wireData := append(block, certBytes...)
		_, _, err := ReadKeysAndCert(wireData)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported certificate type")
	})

	t.Run("SIGNED cert type", func(t *testing.T) {
		block := make([]byte, KEYS_AND_CERT_DATA_SIZE)
		certBytes := []byte{0x03, 0x00, 0x00}
		wireData := append(block, certBytes...)
		_, _, err := ReadKeysAndCert(wireData)
		require.Error(t, err)
	})

	t.Run("unsupported cert type", func(t *testing.T) {
		wireData := make([]byte, KEYS_AND_CERT_DATA_SIZE+3)
		wireData[KEYS_AND_CERT_DATA_SIZE] = 0x02 // HIDDEN cert type
		wireData[KEYS_AND_CERT_DATA_SIZE+1] = 0x00
		wireData[KEYS_AND_CERT_DATA_SIZE+2] = 0x00
		_, _, err := ReadKeysAndCert(wireData)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported certificate type")
	})

	t.Run("insufficient data for X25519AndEd25519", func(t *testing.T) {
		_, _, err := ReadKeysAndCertX25519AndEd25519(make([]byte, 100))
		require.Error(t, err)
	})
}

// ============================================================================
// Certificate() nil safety
// ============================================================================

func TestCertificate_NilSafety(t *testing.T) {
	t.Run("nil receiver returns nil", func(t *testing.T) {
		var kac *KeysAndCert
		cert := kac.Certificate()
		assert.Nil(t, cert, "Certificate() on nil receiver should return nil")
	})

	t.Run("nil KeyCertificate returns nil", func(t *testing.T) {
		kac := &KeysAndCert{
			KeyCertificate: nil,
		}
		cert := kac.Certificate()
		assert.Nil(t, cert, "Certificate() with nil KeyCertificate should return nil")
	})

	t.Run("zero-value struct returns nil", func(t *testing.T) {
		var kac KeysAndCert
		cert := kac.Certificate()
		assert.Nil(t, cert, "Certificate() on zero-value struct should return nil")
	})

	t.Run("valid struct returns non-nil", func(t *testing.T) {
		kac := createValidKeyAndCert(t)
		cert := kac.Certificate()
		require.NotNil(t, cert, "Certificate() on valid struct should return non-nil")
	})
}

// ============================================================================
// Specialized reader cert type validation
// ============================================================================

func TestReadKeysAndCertElgAndEd25519_MismatchedCertTypes(t *testing.T) {
	t.Run("rejects X25519 crypto type", func(t *testing.T) {
		wireData := buildX25519Ed25519Data(t)
		_, _, err := ReadKeysAndCertElgAndEd25519(wireData)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "crypto type mismatch")
	})

	t.Run("rejects P256 signing type", func(t *testing.T) {
		block := make([]byte, KEYS_AND_CERT_DATA_SIZE)
		_, err := rand.Read(block)
		require.NoError(t, err)

		certPayload := buildKeyCertPayload(key_certificate.KEYCERT_SIGN_P256, key_certificate.KEYCERT_CRYPTO_ELG)
		certBytes := []byte{certificate.CERT_KEY}
		lenBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(lenBytes, uint16(len(certPayload)))
		certBytes = append(certBytes, lenBytes...)
		certBytes = append(certBytes, certPayload...)
		wireData := append(block, certBytes...)

		_, _, err = ReadKeysAndCertElgAndEd25519(wireData)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "signing type mismatch")
	})

	t.Run("accepts correct ElGamal+Ed25519 types", func(t *testing.T) {
		wireData := buildElgEd25519Data(t)
		kac, _, err := ReadKeysAndCertElgAndEd25519(wireData)
		require.NoError(t, err)
		require.NotNil(t, kac)
	})
}

func TestReadKeysAndCertX25519AndEd25519_MismatchedCertTypes(t *testing.T) {
	t.Run("rejects ElGamal crypto type", func(t *testing.T) {
		wireData := buildElgEd25519Data(t)
		_, _, err := ReadKeysAndCertX25519AndEd25519(wireData)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "crypto type mismatch")
	})

	t.Run("rejects RedDSA signing type", func(t *testing.T) {
		block := make([]byte, KEYS_AND_CERT_DATA_SIZE)
		_, err := rand.Read(block)
		require.NoError(t, err)

		certPayload := buildKeyCertPayload(key_certificate.KEYCERT_SIGN_REDDSA_ED25519, key_certificate.KEYCERT_CRYPTO_X25519)
		certBytes := []byte{certificate.CERT_KEY}
		lenBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(lenBytes, uint16(len(certPayload)))
		certBytes = append(certBytes, lenBytes...)
		certBytes = append(certBytes, certPayload...)
		wireData := append(block, certBytes...)

		_, _, err = ReadKeysAndCertX25519AndEd25519(wireData)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "signing type mismatch")
	})

	t.Run("accepts correct X25519+Ed25519 types", func(t *testing.T) {
		wireData := buildX25519Ed25519Data(t)
		kac, _, err := ReadKeysAndCertX25519AndEd25519(wireData)
		require.NoError(t, err)
		require.NotNil(t, kac)
	})
}

// ============================================================================
// validateSpecializedReaderCertTypes
// ============================================================================

func TestValidateSpecializedReaderCertTypes(t *testing.T) {
	t.Run("matching types pass", func(t *testing.T) {
		keyCert := buildTestKeyCert(t, key_certificate.KEYCERT_SIGN_ED25519, key_certificate.KEYCERT_CRYPTO_X25519)
		err := validateSpecializedReaderCertTypes(
			keyCert,
			key_certificate.KEYCERT_CRYPTO_X25519,
			key_certificate.KEYCERT_SIGN_ED25519,
			"test",
		)
		assert.NoError(t, err)
	})

	t.Run("crypto mismatch returns error", func(t *testing.T) {
		keyCert := buildTestKeyCert(t, key_certificate.KEYCERT_SIGN_ED25519, key_certificate.KEYCERT_CRYPTO_ELG)
		err := validateSpecializedReaderCertTypes(
			keyCert,
			key_certificate.KEYCERT_CRYPTO_X25519,
			key_certificate.KEYCERT_SIGN_ED25519,
			"test",
		)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "crypto type mismatch")
	})

	t.Run("signing mismatch returns error", func(t *testing.T) {
		keyCert := buildTestKeyCert(t, key_certificate.KEYCERT_SIGN_P256, key_certificate.KEYCERT_CRYPTO_X25519)
		err := validateSpecializedReaderCertTypes(
			keyCert,
			key_certificate.KEYCERT_CRYPTO_X25519,
			key_certificate.KEYCERT_SIGN_ED25519,
			"test",
		)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "signing type mismatch")
	})
}

// ============================================================================
// validateKeySizes – unknown key type rejection (BUG-1 fix)
// ============================================================================

func TestValidateKeySizesRejectsUnknownKeyTypes(t *testing.T) {
	t.Run("unknown crypto type returns error", func(t *testing.T) {
		// Create a keyCert with an unknown crypto type that returns CryptoSize()=0.
		// We use type 99 which is not defined in the spec.
		keyCert := &key_certificate.KeyCertificate{}
		keyCert.SpkType = []byte{0x00, 0x07} // Ed25519 signing
		keyCert.CpkType = []byte{0x00, 0x63} // type 99, unknown
		keyCert.Certificate = *buildCertForType(t, 7, 99)

		kac := &KeysAndCert{
			KeyCertificate:  keyCert,
			ReceivingPublic: createDummyReceivingKey(),
			SigningPublic:   createDummySigningKey(),
		}
		err := kac.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unknown or unsupported crypto key type")
	})

	t.Run("unknown signing type returns error", func(t *testing.T) {
		keyCert := &key_certificate.KeyCertificate{}
		keyCert.SpkType = []byte{0x00, 0x63} // type 99, unknown
		keyCert.CpkType = []byte{0x00, 0x04} // X25519
		keyCert.Certificate = *buildCertForType(t, 99, 4)

		kac := &KeysAndCert{
			KeyCertificate:  keyCert,
			ReceivingPublic: createDummyReceivingKey(),
			SigningPublic:   createDummySigningKey(),
		}
		err := kac.Validate()
		require.Error(t, err)
		// Should fail on crypto first (size check) or signing depending on type
		assert.Error(t, err)
	})
}

// buildCertForType creates a certificate.Certificate with the given type fields.
func buildCertForType(t *testing.T, sigType, cryptoType int) *certificate.Certificate {
	t.Helper()
	payload := make([]byte, 4)
	binary.BigEndian.PutUint16(payload[0:2], uint16(sigType))
	binary.BigEndian.PutUint16(payload[2:4], uint16(cryptoType))
	cert, err := certificate.NewCertificateWithType(certificate.CERT_KEY, payload)
	require.NoError(t, err)
	return cert
}

// ============================================================================
// ReadKeysAndCertElgAndEd25519 with NULL certificate input
// ============================================================================

func TestReadKeysAndCertElgAndEd25519_NullCertInput(t *testing.T) {
	t.Run("rejects NULL certificate", func(t *testing.T) {
		wireData := buildNullCertData(t)
		_, _, err := ReadKeysAndCertElgAndEd25519(wireData)
		require.Error(t, err)
		// Should fail on cert type validation: expects Ed25519(7) but gets DSA-SHA1(0)
	})
}

// ============================================================================
// buildKeysAndCertBlock with nil Padding
// ============================================================================

func TestBuildKeysAndCertBlockNilPadding(t *testing.T) {
	t.Run("nil padding produces zero-filled padding region", func(t *testing.T) {
		keyCert := buildTestKeyCert(t,
			key_certificate.KEYCERT_SIGN_ED25519,
			key_certificate.KEYCERT_CRYPTO_X25519,
		)
		kac := &KeysAndCert{
			KeyCertificate:  keyCert,
			ReceivingPublic: createDummyX25519Key(),
			Padding:         nil, // intentionally nil
			SigningPublic:   createDummySigningKey(),
		}
		block := buildKeysAndCertBlock(kac)
		assert.Equal(t, KEYS_AND_CERT_DATA_SIZE, len(block))

		// The crypto key should be at the start
		assert.Equal(t, kac.ReceivingPublic.Bytes(), block[:32])

		// Padding region should be all zeros since Padding is nil
		paddingRegion := block[32:352]
		for i, b := range paddingRegion {
			if b != 0 {
				t.Errorf("expected zero at padding offset %d, got %d", i, b)
				break
			}
		}

		// Signing key should be at the end
		assert.Equal(t, kac.SigningPublic.Bytes(), block[352:384])
	})
}

// createDummyX25519Key creates a 32-byte X25519 key for testing.
func createDummyX25519Key() types.ReceivingPublicKey {
	key := make(curve25519.Curve25519PublicKey, 32)
	for i := range key {
		key[i] = byte(i % 256)
	}
	return key
}

// ============================================================================
// NewKeysAndCert nil key rejection
// ============================================================================

func TestNewKeysAndCert_NilPublicKeyRejected(t *testing.T) {
	keyCert := buildTestKeyCert(t, key_certificate.KEYCERT_SIGN_ED25519, key_certificate.KEYCERT_CRYPTO_X25519)
	padding := make([]byte, KEYS_AND_CERT_DATA_SIZE-32-32)
	_, err := NewKeysAndCert(keyCert, nil, padding, createDummySigningKey())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "publicKey cannot be nil")
}

func TestNewKeysAndCert_NilSigningKeyRejected(t *testing.T) {
	keyCert := buildTestKeyCert(t, key_certificate.KEYCERT_SIGN_ED25519, key_certificate.KEYCERT_CRYPTO_X25519)
	padding := make([]byte, KEYS_AND_CERT_DATA_SIZE-32-32)
	_, err := NewKeysAndCert(keyCert, createDummyX25519Key(), padding, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "signingPublicKey cannot be nil")
}

// ============================================================================
// validatePublicKeySize / validateSigningKeySize nil key paths
// ============================================================================

func TestValidatePublicKeySize_NilKey(t *testing.T) {
	err := validatePublicKeySize(nil, 32)
	assert.NoError(t, err, "nil public key should pass validatePublicKeySize (nil guard)")
}

func TestValidateSigningKeySize_NilKey(t *testing.T) {
	err := validateSigningKeySize(nil, 32)
	assert.NoError(t, err, "nil signing key should pass validateSigningKeySize (nil guard)")
}
