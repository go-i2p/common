package keys_and_cert

import (
	"encoding/binary"
	"testing"

	"github.com/go-i2p/common/certificate"
	"github.com/go-i2p/common/key_certificate"

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
