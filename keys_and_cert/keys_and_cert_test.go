package keys_and_cert

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/go-i2p/crypto/ed25519"
	"github.com/go-i2p/crypto/types"

	"github.com/go-i2p/common/certificate"
	"github.com/go-i2p/common/data"
	"github.com/go-i2p/common/key_certificate"
	elgamal "github.com/go-i2p/crypto/elg"

	"github.com/stretchr/testify/assert"
)

/*
func TestCertificateWithMissingData(t *testing.T) {
	assert := assert.New(t)

	cert_data := []byte{0x05, 0x00, 0x04, 0x00, 0x01}
	data := make([]byte, 128+256)
	data = append(data, cert_data...)
	_, _, err := NewKeysAndCert(data)
	if assert.NotNil(err) {
		assert.Equal("certificate parsing warning: certificate data is shorter than specified by length", err.Error())
	}
}

*/

// createValidKeyCertificate creates a valid KeyCertificate for testing.
func createValidKeyAndCert(t *testing.T) *KeysAndCert {
	// Generate signing key pair (Ed25519)
	// var ed25519_privkey crypto.Ed25519PrivateKey
	ed25519_privkey, err := ed25519.GenerateEd25519Key()
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 private %s", err)
	}
	// Copy the full private key (includes public key)
	//ed25519_privkey := make(ed25519.Ed25519PrivateKey, ed25519.PrivateKeySize)
	//copy(ed25519_privkey, priv)
	//_, err = (ed25519_privkey).Generate()
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 private key: %v\n", err)
	}
	ed25519_pubkey_raw, err := ed25519_privkey.Public()
	if err != nil {
		t.Fatalf("Failed to derive Ed25519 public key: %v\n", err)
	}
	ed25519_pubkey, ok := ed25519_pubkey_raw.(types.SigningPublicKey)
	if !ok {
		t.Fatalf("Failed to get SigningPublicKey from Ed25519 public key")
	}

	// Generate encryption key pair (ElGamal)
	var elgamal_privkey elgamal.PrivateKey
	err = elgamal.ElgamalGenerate(&elgamal_privkey.PrivateKey, rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ElGamal private key: %v\n", err)
	}

	// Convert elgamal public key to crypto.ElgPublicKey
	var elg_pubkey elgamal.ElgPublicKey
	yBytes := elgamal_privkey.PublicKey.Y.Bytes()
	if len(yBytes) > 256 {
		t.Fatalf("ElGamal public key Y too large")
	}
	copy(elg_pubkey[256-len(yBytes):], yBytes)

	// Create KeyCertificate specifying key types
	var payload bytes.Buffer
	cryptoPublicKeyType, err := data.NewIntegerFromInt(0, 2) // ElGamal
	if err != nil {
		t.Fatalf("Failed to create crypto public key type integer: %v", err)
	}

	signingPublicKeyType, err := data.NewIntegerFromInt(7, 2) // Ed25519
	if err != nil {
		t.Fatalf("Failed to create signing public key type integer: %v", err)
	}
	payload.Write(*signingPublicKeyType)
	payload.Write(*cryptoPublicKeyType)

	// Create certificate
	cert, err := certificate.NewCertificateWithType(certificate.CERT_KEY, payload.Bytes())
	if err != nil {
		t.Fatalf("Failed to create new certificate: %v\n", err)
	}

	keyCert, err := key_certificate.KeyCertificateFromCertificate(cert)
	if err != nil {
		t.Fatalf("KeyCertificateFromCertificate failed: %v\n", err)
	}
	pubKeySize := keyCert.CryptoSize()
	sigKeySize := keyCert.SigningPublicKeySize()
	paddingSize := KEYS_AND_CERT_DATA_SIZE - pubKeySize - sigKeySize
	// Generate random padding
	padding := make([]byte, paddingSize)
	_, err = rand.Read(padding)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("pubkey len: %v\n", ed25519_pubkey.Len())
	t.Logf("pubkey bytes: %v\n", ed25519_pubkey.Bytes())

	keysAndCert, err := NewKeysAndCert(keyCert, elg_pubkey, padding, ed25519_pubkey)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("pubkey bytes after NewKeysAndCert: %v\n", keysAndCert.SigningPublic.Bytes())

	return keysAndCert
}

func TestCertificateWithValidDataElgAndEd25519(t *testing.T) {
	assert := assert.New(t)
	keysAndCert := createValidKeyAndCert(t)

	// Serialize KeysAndCert to bytes
	serialized, err := keysAndCert.Bytes()
	assert.Nil(err, "Bytes() should not error for valid KeysAndCert")

	// Deserialize KeysAndCert from bytes
	parsedKeysAndCert, remainder, err := ReadKeysAndCertElgAndEd25519(serialized)
	assert.Nil(err, "ReadKeysAndCert should not error with valid data")
	assert.Empty(remainder, "There should be no remainder after parsing KeysAndCert")

	// Compare individual fields
	assert.Equal(keysAndCert.KeyCertificate.Bytes(), parsedKeysAndCert.KeyCertificate.Bytes(), "KeyCertificates should match")
	assert.Equal(keysAndCert.ReceivingPublic.Bytes(), parsedKeysAndCert.ReceivingPublic.Bytes(), "PublicKeys should match")
	assert.Equal(keysAndCert.Padding, parsedKeysAndCert.Padding, "Padding should match")
	assert.Equal(keysAndCert.SigningPublic.Bytes(), parsedKeysAndCert.SigningPublic.Bytes(), "SigningPublicKeys should match")
}

func TestCertificateWithValidDataManual(t *testing.T) {
	assert := assert.New(t)

	cert_data := []byte{0x05, 0x00, 0x04, 0x00, 0x01, 0x00, 0x00}
	data := make([]byte, 128+256)
	data = append(data, cert_data...)
	keys_and_cert, _, err := ReadKeysAndCert(data)
	assert.Nil(err)

	cert := keys_and_cert.Certificate()

	cert_bytes := cert.Bytes()
	if assert.Equal(len(cert_data), len(cert_bytes)) {
		assert.Equal(cert_bytes, cert_data, "keys_and_cert.Certificate() did not return correct data with valid cert")
	}
}

func TestPublicKeyWithBadData(t *testing.T) {
	assert := assert.New(t)

	cert_data := []byte{0x05, 0x00, 0x04, 0x00, 0x01, 0x00, 0x00}
	pub_key_data := make([]byte, 193)
	data := make([]byte, 128)
	data = append(data, pub_key_data...)
	data = append(data, cert_data...)
	keys_and_cert, _, err := ReadKeysAndCert(data)

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
	data := make([]byte, 128)
	data = append(data, pub_key_data...)
	data = append(data, cert_data...)
	keys_and_cert, _, err := ReadKeysAndCert(data)

	if assert.NotNil(err) {
		log.WithError(err).Debug("Correctly got error")
	}
	pub_key, pub_key_err := keys_and_cert.PublicKey()
	assert.NotNil(pub_key_err)
	assert.Nil(pub_key)
}

/*
	func TestPublicKeyWithNullCertificate(t *testing.T) {
		assert := assert.New(t)

		cert_data := []byte{0x00, 0x00, 0x00}
		pub_key_data := make([]byte, 256)
		data := make([]byte, 128)
		data = append(data, pub_key_data...)
		data = append(data, cert_data...)
		keys_and_cert, _, err := ReadKeysAndCert(data)

		pub_key := keys_and_cert.PublicKey()
		assert.Nil(err)
		assert.Equal(len(pub_key_data), pub_key.Len())
	}

	func TestPublicKeyWithKeyCertificate(t *testing.T) {
		assert := assert.New(t)

		cert_data := []byte{0x05, 0x00, 0x04, 0x00, 0x01, 0x00, 0x00}
		pub_key_data := make([]byte, 256)
		data := make([]byte, 128)
		data = append(data, pub_key_data...)
		data = append(data, cert_data...)
		keys_and_cert, _, err := ReadKeysAndCert(data)

		pub_key := keys_and_cert.PublicKey()
		assert.Nil(err)
		assert.Equal(len(pub_key_data), pub_key.Len())
	}
*/
func TestSigningPublicKeyWithBadData(t *testing.T) {
	assert := assert.New(t)

	cert_data := []byte{0x05, 0x00, 0x04, 0x00, 0x01, 0x00, 0x00}
	pub_key_data := make([]byte, 256)
	data := make([]byte, 93)
	data = append(data, pub_key_data...)
	data = append(data, cert_data...)
	keys_and_cert, _, err := ReadKeysAndCert(data)

	signing_pub_key, signing_key_err := keys_and_cert.SigningPublicKey()
	assert.NotNil(err)
	assert.NotNil(signing_key_err)
	assert.Nil(signing_pub_key)
}

func TestSigningPublicKeyWithBadCertificate(t *testing.T) {
	assert := assert.New(t)

	cert_data := []byte{0x05, 0x00, 0x04, 0x00, 0x01}
	pub_key_data := make([]byte, 256)
	data := make([]byte, 128)
	data = append(data, pub_key_data...)
	data = append(data, cert_data...)
	keys_and_cert, _, err := ReadKeysAndCert(data)
	signing_pub_key, signing_key_err := keys_and_cert.SigningPublicKey()
	assert.NotNil(err)
	assert.NotNil(signing_key_err)
	assert.Nil(signing_pub_key)
}

/*
func TestSigningPublicKeyWithNullCertificate(t *testing.T) {
	assert := assert.New(t)

	cert_data := []byte{0x00, 0x00, 0x00}
	pub_key_data := make([]byte, 256)
	signing_pub_key_data := make([]byte, 128)
	data := append(pub_key_data, signing_pub_key_data...)
	data = append(data, cert_data...)
	keys_and_cert, _, err := ReadKeysAndCert(data)

	signing_pub_key := keys_and_cert.SigningPublicKey()
	assert.Nil(err)
	assert.Equal(len(signing_pub_key_data), signing_pub_key.Len())
}

func TestSigningPublicKeyWithKeyCertificate(t *testing.T) {
	assert := assert.New(t)

	cert_data := []byte{0x05, 0x00, 0x04, 0x00, 0x01, 0x00, 0x00}
	pub_key_data := make([]byte, 256)
	signing_pub_key_data := make([]byte, 128)
	data := append(pub_key_data, signing_pub_key_data...)
	data = append(data, cert_data...)
	keys_and_cert, _, err := ReadKeysAndCert(data)

	signing_pub_key := keys_and_cert.SigningPublicKey()
	assert.Nil(err)
	assert.Equal(len(signing_pub_key_data), signing_pub_key.Len())
}

*/

func TestNewKeysAndCertWithMissingData(t *testing.T) {
	assert := assert.New(t)

	cert_data := make([]byte, 128)
	_, remainder, err := ReadKeysAndCert(cert_data)
	assert.Equal(0, len(remainder))
	if assert.NotNil(err) {
		assert.Equal("error parsing KeysAndCert: data is smaller than minimum valid size", err.Error())
	}
}

/*
	func TestNewKeysAndCertWithMissingCertData(t *testing.T) {
		assert := assert.New(t)

		cert_data := make([]byte, 128+256)
		cert_data = append(cert_data, []byte{0x05, 0x00, 0x04, 0x00, 0x01}...)
		_, remainder, err := ReadKeysAndCertDeux(cert_data)
		assert.Equal(0, len(remainder))
		if assert.NotNil(err) {
			assert.Equal("certificate parsing warning: certificate data is shorter than specified by length", err.Error())
		}
	}
*/
func TestNewKeysAndCertWithValidDataWithCertificate(t *testing.T) {
	assert := assert.New(t)

	cert_data := make([]byte, 128+256)
	cert_data = append(cert_data, []byte{0x05, 0x00, 0x04, 0x00, 0x01, 0x00, 0x00}...)
	_, remainder, err := ReadKeysAndCert(cert_data)
	assert.Equal(0, len(remainder))
	assert.Nil(err)
}

/*
	func TestNewKeysAndCertWithValidDataWithoutCertificate(t *testing.T) {
		assert := assert.New(t)

		cert_data := make([]byte, 128+256)
		cert_data = append(cert_data, []byte{0x00, 0x00, 0x00}...)
		_, remainder, err := ReadKeysAndCert(cert_data)
		assert.Equal(0, len(remainder))
		assert.Nil(err)
	}
*/
func TestNewKeysAndCertWithValidDataWithCertificateAndRemainder(t *testing.T) {
	assert := assert.New(t)

	cert_data := make([]byte, 128+256)
	cert_data = append(cert_data, []byte{0x05, 0x00, 0x04, 0x00, 0x01, 0x00, 0x00, 0x41}...)
	_, remainder, err := ReadKeysAndCert(cert_data)
	if assert.Equal(1, len(remainder)) {
		assert.Equal("A", string(remainder[0]))
	}
	assert.Nil(err)
}

/*
func TestNewKeysAndCertWithValidDataWithoutCertificateAndRemainder(t *testing.T) {
	assert := assert.New(t)

	cert_data := make([]byte, 128+256)
	cert_data = append(cert_data, []byte{0x00, 0x00, 0x00, 0x41}...)
	_, remainder, err := ReadKeysAndCert(cert_data)
	if assert.Equal(1, len(remainder)) {
		assert.Equal("A", string(remainder[0]))
	}
	assert.Nil(err)
}


*/

// TestValidate tests the Validate() method for various edge cases
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

// TestIsValid tests the IsValid() convenience method
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

// TestZeroValueKeysAndCertUnsafe tests that a zero-value KeysAndCert is unsafe
func TestZeroValueKeysAndCertUnsafe(t *testing.T) {
	assert := assert.New(t)

	var kac KeysAndCert
	assert.False(kac.IsValid())

	_, err := kac.Bytes()
	assert.NotNil(err)
	assert.Contains(err.Error(), "KeyCertificate is required")
}

// TestBytesWithInvalidStruct tests that Bytes() returns error for invalid structs
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

// TestPublicKeyAndSigningPublicKeyValidation tests validation in accessor methods
func TestPublicKeyAndSigningPublicKeyValidation(t *testing.T) {
	assert := assert.New(t)

	t.Run("PublicKey returns error on invalid struct", func(t *testing.T) {
		kac := &KeysAndCert{}
		_, err := kac.PublicKey()
		assert.NotNil(err)
	})

	t.Run("SigningPublicKey returns error on invalid struct", func(t *testing.T) {
		kac := &KeysAndCert{}
		_, err := kac.SigningPublicKey()
		assert.NotNil(err)
	})

	t.Run("PublicKey returns key on valid struct", func(t *testing.T) {
		kac := createValidKeyAndCert(t)
		key, err := kac.PublicKey()
		assert.Nil(err)
		assert.NotNil(key)
	})

	t.Run("SigningPublicKey returns key on valid struct", func(t *testing.T) {
		kac := createValidKeyAndCert(t)
		key, err := kac.SigningPublicKey()
		assert.Nil(err)
		assert.NotNil(key)
	})
}

// TestReadKeysAndCertReturnsNilOnError tests that ReadKeysAndCert returns nil on error
func TestReadKeysAndCertReturnsNilOnError(t *testing.T) {
	assert := assert.New(t)

	t.Run("returns nil on insufficient data", func(t *testing.T) {
		data := make([]byte, 10)
		kac, _, err := ReadKeysAndCert(data)
		assert.NotNil(err)
		assert.Nil(kac)
	})

	t.Run("returns nil on certificate parse error", func(t *testing.T) {
		// Create data that's long enough but has invalid certificate
		data := make([]byte, KEYS_AND_CERT_DATA_SIZE+3)
		// Set invalid certificate type
		data[KEYS_AND_CERT_DATA_SIZE] = 0xFF
		kac, _, err := ReadKeysAndCert(data)
		assert.NotNil(err)
		assert.Nil(kac)
	})
}

// TestRoundTripKeysAndCert tests round-trip serialization and deserialization
func TestRoundTripKeysAndCert(t *testing.T) {
	assert := assert.New(t)

	original := createValidKeyAndCert(t)
	assert.True(original.IsValid())

	// Serialize
	serialized, err := original.Bytes()
	assert.Nil(err)
	assert.NotEmpty(serialized)

	// Deserialize
	parsed, remainder, err := ReadKeysAndCert(serialized)
	assert.Nil(err)
	assert.Empty(remainder)
	assert.NotNil(parsed)
	assert.True(parsed.IsValid())

	// Compare fields
	assert.Equal(original.KeyCertificate.Bytes(), parsed.KeyCertificate.Bytes())
	assert.Equal(original.ReceivingPublic.Bytes(), parsed.ReceivingPublic.Bytes())
	assert.Equal(original.Padding, parsed.Padding)
	assert.Equal(original.SigningPublic.Bytes(), parsed.SigningPublic.Bytes())
}

// Helper functions for creating test data

// createDummyKeyCertificate creates a basic KeyCertificate for testing
func createDummyKeyCertificate(t *testing.T) *key_certificate.KeyCertificate {
	var payload bytes.Buffer
	cryptoPublicKeyType, err := data.NewIntegerFromInt(0, 2) // ElGamal
	if err != nil {
		t.Fatalf("Failed to create crypto public key type: %v", err)
	}
	signingPublicKeyType, err := data.NewIntegerFromInt(7, 2) // Ed25519
	if err != nil {
		t.Fatalf("Failed to create signing public key type: %v", err)
	}
	payload.Write(*signingPublicKeyType)
	payload.Write(*cryptoPublicKeyType)

	cert, err := certificate.NewCertificateWithType(certificate.CERT_KEY, payload.Bytes())
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	keyCert, err := key_certificate.KeyCertificateFromCertificate(cert)
	if err != nil {
		t.Fatalf("Failed to create KeyCertificate: %v", err)
	}
	return keyCert
}

// createDummyReceivingKey creates a dummy ElGamal public key for testing
func createDummyReceivingKey() types.ReceivingPublicKey {
	var key elgamal.ElgPublicKey
	// Fill with non-zero data to make it valid
	for i := range key {
		key[i] = byte(i % 256)
	}
	return key
}

// createDummySigningKey creates a dummy Ed25519 public key for testing
func createDummySigningKey() types.SigningPublicKey {
	keyData := make([]byte, 32)
	// Fill with non-zero data to make it valid
	for i := range keyData {
		keyData[i] = byte(i % 256)
	}
	key, _ := ed25519.NewEd25519PublicKey(keyData)
	return key
}
