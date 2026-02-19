package keys_and_cert

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"testing"

	"github.com/go-i2p/common/certificate"
	"github.com/go-i2p/common/data"
	"github.com/go-i2p/common/key_certificate"
	"github.com/go-i2p/crypto/ed25519"
	elgamal "github.com/go-i2p/crypto/elg"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============================================================================
// ReadKeysAndCert – X25519+Ed25519
// ============================================================================

func TestReadKeysAndCert_X25519Ed25519(t *testing.T) {
	t.Run("parses without panic", func(t *testing.T) {
		wireData := buildX25519Ed25519Data(t)
		kac, remainder, err := ReadKeysAndCert(wireData)
		require.NoError(t, err)
		assert.Empty(t, remainder)
		require.NotNil(t, kac)
		assert.NotNil(t, kac.ReceivingPublic)
		assert.NotNil(t, kac.SigningPublic)
		assert.Equal(t, 32, kac.ReceivingPublic.Len(), "X25519 key should be 32 bytes")
		assert.Equal(t, 32, kac.SigningPublic.Len(), "Ed25519 key should be 32 bytes")
	})

	t.Run("extracts correct key bytes", func(t *testing.T) {
		wireData := buildX25519Ed25519Data(t)
		expectedCryptoKey := wireData[0:32]
		expectedSigningKey := wireData[KEYS_AND_CERT_DATA_SIZE-32 : KEYS_AND_CERT_DATA_SIZE]

		kac, _, err := ReadKeysAndCert(wireData)
		require.NoError(t, err)
		assert.Equal(t, expectedCryptoKey, kac.ReceivingPublic.Bytes())
		assert.Equal(t, expectedSigningKey, kac.SigningPublic.Bytes())
	})

	t.Run("round-trip serialization", func(t *testing.T) {
		wireData := buildX25519Ed25519Data(t)
		kac, _, err := ReadKeysAndCert(wireData)
		require.NoError(t, err)

		serialized, err := kac.Bytes()
		require.NoError(t, err)
		assert.Equal(t, wireData, serialized, "round-trip should produce identical wire data")
	})

	t.Run("padding is correct length", func(t *testing.T) {
		wireData := buildX25519Ed25519Data(t)
		kac, _, err := ReadKeysAndCert(wireData)
		require.NoError(t, err)
		assert.Equal(t, 320, len(kac.Padding), "padding should be 320 bytes for X25519+Ed25519")
	})
}

// ============================================================================
// ReadKeysAndCert – NULL certificate (ElGamal + DSA-SHA1)
// ============================================================================

func TestReadKeysAndCert_NullCertificate(t *testing.T) {
	t.Run("parses without error", func(t *testing.T) {
		wireData := buildNullCertData(t)
		kac, remainder, err := ReadKeysAndCert(wireData)
		require.NoError(t, err)
		assert.Empty(t, remainder)
		require.NotNil(t, kac)
		assert.NotNil(t, kac.ReceivingPublic)
		assert.NotNil(t, kac.SigningPublic)
	})

	t.Run("ElGamal key is 256 bytes", func(t *testing.T) {
		wireData := buildNullCertData(t)
		kac, _, err := ReadKeysAndCert(wireData)
		require.NoError(t, err)
		assert.Equal(t, 256, kac.ReceivingPublic.Len())
	})

	t.Run("DSA-SHA1 key is 128 bytes", func(t *testing.T) {
		wireData := buildNullCertData(t)
		kac, _, err := ReadKeysAndCert(wireData)
		require.NoError(t, err)
		assert.Equal(t, 128, kac.SigningPublic.Len())
	})

	t.Run("no padding for ElGamal+DSA-SHA1", func(t *testing.T) {
		wireData := buildNullCertData(t)
		kac, _, err := ReadKeysAndCert(wireData)
		require.NoError(t, err)
		assert.Nil(t, kac.Padding, "no padding needed for ElGamal(256)+DSA-SHA1(128)")
	})

	t.Run("key bytes match wire data", func(t *testing.T) {
		wireData := buildNullCertData(t)
		kac, _, err := ReadKeysAndCert(wireData)
		require.NoError(t, err)
		assert.Equal(t, wireData[:256], kac.ReceivingPublic.Bytes())
		assert.Equal(t, wireData[256:384], kac.SigningPublic.Bytes())
	})

	t.Run("round-trip serialization", func(t *testing.T) {
		wireData := buildNullCertData(t)
		kac, _, err := ReadKeysAndCert(wireData)
		require.NoError(t, err)

		serialized, err := kac.Bytes()
		require.NoError(t, err)
		assert.Equal(t, wireData[:384], serialized[:384], "384-byte block should match")
	})

	t.Run("with remainder", func(t *testing.T) {
		wireData := buildNullCertData(t)
		wireData = append(wireData, 0xAA, 0xBB)
		kac, remainder, err := ReadKeysAndCert(wireData)
		require.NoError(t, err)
		require.NotNil(t, kac)
		assert.Equal(t, []byte{0xAA, 0xBB}, remainder)
	})
}

// ============================================================================
// ReadKeysAndCert – NULL cert DSA key type assertions
// ============================================================================

func TestReadKeysAndCert_NullCertDSAKeyType(t *testing.T) {
	wireData := buildNullCertData(t)
	kac, _, err := ReadKeysAndCert(wireData)
	require.NoError(t, err)

	assert.Equal(t, 128, kac.SigningPublic.Len(),
		"NULL certificate should produce DSA-SHA1 signing key (128 bytes)")
	assert.Equal(t, 256, kac.ReceivingPublic.Len(),
		"NULL certificate should produce ElGamal public key (256 bytes)")
	assert.Equal(t, 0, kac.KeyCertificate.SigningPublicKeyType(),
		"NULL cert should report signing type 0 (DSA-SHA1)")
	assert.Equal(t, 0, kac.KeyCertificate.PublicKeyType(),
		"NULL cert should report crypto type 0 (ElGamal)")
}

// ============================================================================
// ReadKeysAndCert – X25519 crypto type assertion
// ============================================================================

func TestReadKeysAndCert_X25519CryptoType(t *testing.T) {
	wireData := buildX25519Ed25519Data(t)
	kac, _, err := ReadKeysAndCert(wireData)
	require.NoError(t, err)

	pubKeyType := kac.KeyCertificate.PublicKeyType()
	assert.Equal(t, key_certificate.KEYCERT_CRYPTO_X25519, pubKeyType)

	sigKeyType := kac.KeyCertificate.SigningPublicKeyType()
	assert.Equal(t, key_certificate.KEYCERT_SIGN_ED25519, sigKeyType)
}

// ============================================================================
// ReadKeysAndCert – Various signing types
// ============================================================================

func TestReadKeysAndCert_VariousSigningTypes(t *testing.T) {
	validTypes := []struct {
		name    string
		sigType int
		keySize int
	}{
		{"P256", key_certificate.KEYCERT_SIGN_P256, 64},
		{"P384", key_certificate.KEYCERT_SIGN_P384, 96},
		{"Ed25519ph", key_certificate.KEYCERT_SIGN_ED25519PH, 32},
		{"RedDSA", key_certificate.KEYCERT_SIGN_REDDSA_ED25519, 32},
	}
	for _, tt := range validTypes {
		t.Run(tt.name, func(t *testing.T) {
			block := make([]byte, KEYS_AND_CERT_DATA_SIZE)
			_, err := rand.Read(block[KEYS_AND_CERT_DATA_SIZE-tt.keySize : KEYS_AND_CERT_DATA_SIZE])
			require.NoError(t, err)

			certPayload := buildKeyCertPayload(tt.sigType, key_certificate.KEYCERT_CRYPTO_ELG)
			certBytes := []byte{certificate.CERT_KEY}
			lenBytes := make([]byte, 2)
			binary.BigEndian.PutUint16(lenBytes, uint16(len(certPayload)))
			certBytes = append(certBytes, lenBytes...)
			certBytes = append(certBytes, certPayload...)
			wireData := append(block, certBytes...)

			kac, _, err := ReadKeysAndCert(wireData)
			require.NoError(t, err, "should parse %s signing type without error", tt.name)
			require.NotNil(t, kac)
			assert.NotNil(t, kac.SigningPublic, "signing key should not be nil for %s", tt.name)
		})
	}
}

// ============================================================================
// ReadKeysAndCertElgAndEd25519
// ============================================================================

func TestCertificateWithValidDataElgAndEd25519(t *testing.T) {
	assert := assert.New(t)
	keysAndCert := createValidKeyAndCert(t)

	serialized, err := keysAndCert.Bytes()
	assert.Nil(err, "Bytes() should not error for valid KeysAndCert")

	parsedKeysAndCert, remainder, err := ReadKeysAndCertElgAndEd25519(serialized)
	assert.Nil(err, "ReadKeysAndCert should not error with valid data")
	assert.Empty(remainder, "There should be no remainder after parsing KeysAndCert")

	assert.Equal(keysAndCert.KeyCertificate.Bytes(), parsedKeysAndCert.KeyCertificate.Bytes(), "KeyCertificates should match")
	assert.Equal(keysAndCert.ReceivingPublic.Bytes(), parsedKeysAndCert.ReceivingPublic.Bytes(), "PublicKeys should match")
	assert.Equal(keysAndCert.Padding, parsedKeysAndCert.Padding, "Padding should match")
	assert.Equal(keysAndCert.SigningPublic.Bytes(), parsedKeysAndCert.SigningPublic.Bytes(), "SigningPublicKeys should match")
}

// ============================================================================
// ReadKeysAndCertX25519AndEd25519
// ============================================================================

func TestReadKeysAndCertX25519AndEd25519(t *testing.T) {
	t.Run("parses valid data", func(t *testing.T) {
		wireData := buildX25519Ed25519Data(t)
		kac, remainder, err := ReadKeysAndCertX25519AndEd25519(wireData)
		require.NoError(t, err)
		assert.Empty(t, remainder)
		require.NotNil(t, kac)
		assert.Equal(t, 32, kac.ReceivingPublic.Len())
		assert.Equal(t, 32, kac.SigningPublic.Len())
	})

	t.Run("extracts correct key bytes", func(t *testing.T) {
		wireData := buildX25519Ed25519Data(t)
		expectedCrypto := wireData[0:32]
		expectedSigning := wireData[KEYS_AND_CERT_DATA_SIZE-32 : KEYS_AND_CERT_DATA_SIZE]

		kac, _, err := ReadKeysAndCertX25519AndEd25519(wireData)
		require.NoError(t, err)
		assert.Equal(t, expectedCrypto, kac.ReceivingPublic.Bytes())
		assert.Equal(t, expectedSigning, kac.SigningPublic.Bytes())
	})

	t.Run("with remainder", func(t *testing.T) {
		wireData := buildX25519Ed25519Data(t)
		wireData = append(wireData, 0xCC, 0xDD)
		kac, remainder, err := ReadKeysAndCertX25519AndEd25519(wireData)
		require.NoError(t, err)
		require.NotNil(t, kac)
		assert.Equal(t, []byte{0xCC, 0xDD}, remainder)
	})
}

// ============================================================================
// ReadKeysAndCert with manual cert data
// ============================================================================

func TestCertificateWithValidDataManual(t *testing.T) {
	assert := assert.New(t)

	cert_data := []byte{0x05, 0x00, 0x04, 0x00, 0x01, 0x00, 0x00}
	d := make([]byte, 128+256)
	d = append(d, cert_data...)
	keys_and_cert, _, err := ReadKeysAndCert(d)
	assert.Nil(err)

	cert := keys_and_cert.Certificate()
	cert_bytes := cert.Bytes()
	if assert.Equal(len(cert_data), len(cert_bytes)) {
		assert.Equal(cert_bytes, cert_data, "keys_and_cert.Certificate() did not return correct data with valid cert")
	}
}

// ============================================================================
// ReadKeysAndCert with certificate and remainder
// ============================================================================

func TestNewKeysAndCertWithValidDataWithCertificate(t *testing.T) {
	assert := assert.New(t)

	cert_data := make([]byte, 128+256)
	cert_data = append(cert_data, []byte{0x05, 0x00, 0x04, 0x00, 0x01, 0x00, 0x00}...)
	_, remainder, err := ReadKeysAndCert(cert_data)
	assert.Equal(0, len(remainder))
	assert.Nil(err)
}

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

// ============================================================================
// Bytes() output size
// ============================================================================

func TestBytesOutputSize(t *testing.T) {
	t.Run("ElGamal+Ed25519 produces 384+certLen bytes", func(t *testing.T) {
		kac := createValidKeyAndCert(t)
		serialized, err := kac.Bytes()
		require.NoError(t, err)

		certBytes := kac.KeyCertificate.Bytes()
		expectedLen := KEYS_AND_CERT_DATA_SIZE + len(certBytes)
		assert.Equal(t, expectedLen, len(serialized),
			"Bytes() must produce exactly 384 + cert_length bytes")
		assert.GreaterOrEqual(t, len(serialized), KEYS_AND_CERT_MIN_SIZE,
			"Bytes() output must be at least 387 bytes")
	})

	t.Run("X25519+Ed25519 produces 384+certLen bytes", func(t *testing.T) {
		kac := createX25519Ed25519KeysAndCert(t)
		serialized, err := kac.Bytes()
		require.NoError(t, err)

		certBytes := kac.KeyCertificate.Bytes()
		expectedLen := KEYS_AND_CERT_DATA_SIZE + len(certBytes)
		assert.Equal(t, expectedLen, len(serialized))
		assert.GreaterOrEqual(t, len(serialized), KEYS_AND_CERT_MIN_SIZE)
	})
}

// ============================================================================
// Bytes() produces correct wire format
// ============================================================================

func TestBytesProducesCorrectWireFormat_ElgEd25519(t *testing.T) {
	wireData := buildElgEd25519Data(t)
	kac, _, err := ReadKeysAndCert(wireData)
	require.NoError(t, err)

	serialized, err := kac.Bytes()
	require.NoError(t, err)
	assert.Equal(t, wireData, serialized, "ElGamal+Ed25519 round-trip should be exact")
}

// ============================================================================
// NewKeysAndCert – constructor paths
// ============================================================================

func TestNewKeysAndCert_X25519Ed25519(t *testing.T) {
	kac := createX25519Ed25519KeysAndCert(t)

	t.Run("creates valid struct", func(t *testing.T) {
		assert.True(t, kac.IsValid())
		assert.Equal(t, 32, kac.ReceivingPublic.Len())
		assert.Equal(t, 32, kac.SigningPublic.Len())
	})

	t.Run("round-trips through serialization", func(t *testing.T) {
		serialized, err := kac.Bytes()
		require.NoError(t, err)

		parsed, remainder, err := ReadKeysAndCert(serialized)
		require.NoError(t, err)
		assert.Empty(t, remainder)
		assert.Equal(t, kac.ReceivingPublic.Bytes(), parsed.ReceivingPublic.Bytes())
		assert.Equal(t, kac.SigningPublic.Bytes(), parsed.SigningPublic.Bytes())
		assert.Equal(t, kac.Padding, parsed.Padding)
	})

	t.Run("key certificate reports correct types", func(t *testing.T) {
		assert.Equal(t, key_certificate.KEYCERT_CRYPTO_X25519, kac.KeyCertificate.PublicKeyType())
		assert.Equal(t, key_certificate.KEYCERT_SIGN_ED25519, kac.KeyCertificate.SigningPublicKeyType())
	})
}

func TestNewKeysAndCertElgEd25519_RoundTrip(t *testing.T) {
	ed25519Priv, err := ed25519.GenerateEd25519Key()
	require.NoError(t, err)
	ed25519PubRaw, err := ed25519Priv.Public()
	require.NoError(t, err)
	ed25519Pub, ok := ed25519PubRaw.(interface{ Bytes() []byte })
	require.True(t, ok)

	var elgPub elgamal.ElgPublicKey
	_, err = rand.Read(elgPub[:])
	require.NoError(t, err)

	var payload bytes.Buffer
	cryptoType, err := data.NewIntegerFromInt(0, 2) // ElGamal
	require.NoError(t, err)
	sigType, err := data.NewIntegerFromInt(7, 2) // Ed25519
	require.NoError(t, err)
	payload.Write(*sigType)
	payload.Write(*cryptoType)
	cert, err := certificate.NewCertificateWithType(certificate.CERT_KEY, payload.Bytes())
	require.NoError(t, err)
	keyCert, err := key_certificate.KeyCertificateFromCertificate(cert)
	require.NoError(t, err)

	pubKeySize := keyCert.CryptoSize()
	sigKeySize := keyCert.SigningPublicKeySize()
	paddingSize := KEYS_AND_CERT_DATA_SIZE - pubKeySize - sigKeySize
	padding := make([]byte, paddingSize)
	_, err = rand.Read(padding)
	require.NoError(t, err)

	ed25519PubKey, err := ed25519.NewEd25519PublicKey(ed25519Pub.Bytes())
	require.NoError(t, err)

	kac, err := NewKeysAndCert(keyCert, elgPub, padding, ed25519PubKey)
	require.NoError(t, err)

	serialized, err := kac.Bytes()
	require.NoError(t, err)

	parsed, remainder, err := ReadKeysAndCert(serialized)
	require.NoError(t, err)
	assert.Empty(t, remainder)

	assert.Equal(t, kac.ReceivingPublic.Bytes(), parsed.ReceivingPublic.Bytes())
	assert.Equal(t, kac.SigningPublic.Bytes(), parsed.SigningPublic.Bytes())
}

// ============================================================================
// PublicKey / SigningPublicKey accessor methods
// ============================================================================

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

// ============================================================================
// Certificate() accessor
// ============================================================================

// (tested indirectly by TestCertificateWithValidDataManual)

// ============================================================================
// GenerateCompressiblePadding
// ============================================================================

func TestGenerateCompressiblePadding(t *testing.T) {
	t.Run("generates correct size", func(t *testing.T) {
		padding, err := GenerateCompressiblePadding(320)
		require.NoError(t, err)
		assert.Equal(t, 320, len(padding))
	})

	t.Run("repeats 32-byte pattern", func(t *testing.T) {
		padding, err := GenerateCompressiblePadding(64)
		require.NoError(t, err)
		assert.Equal(t, padding[:32], padding[32:64], "padding should repeat 32-byte seed")
	})

	t.Run("handles size < 32", func(t *testing.T) {
		padding, err := GenerateCompressiblePadding(16)
		require.NoError(t, err)
		assert.Equal(t, 16, len(padding))
	})

	t.Run("handles size = 0", func(t *testing.T) {
		padding, err := GenerateCompressiblePadding(0)
		require.NoError(t, err)
		assert.Nil(t, padding)
	})

	t.Run("handles negative size", func(t *testing.T) {
		padding, err := GenerateCompressiblePadding(-1)
		require.NoError(t, err)
		assert.Nil(t, padding)
	})

	t.Run("non-zero content", func(t *testing.T) {
		padding, err := GenerateCompressiblePadding(32)
		require.NoError(t, err)
		allZero := true
		for _, b := range padding {
			if b != 0 {
				allZero = false
				break
			}
		}
		assert.False(t, allZero, "padding should not be all zeros")
	})
}

func TestGenerateCompressiblePaddingUniqueness(t *testing.T) {
	const count = 10
	paddings := make([][]byte, count)
	for i := 0; i < count; i++ {
		p, err := GenerateCompressiblePadding(320)
		require.NoError(t, err)
		paddings[i] = p
	}

	allSame := true
	for i := 1; i < count; i++ {
		if !bytes.Equal(paddings[0], paddings[i]) {
			allSame = false
			break
		}
	}
	assert.False(t, allSame, "GenerateCompressiblePadding should produce different outputs on different calls")
}

// ============================================================================
// extractPaddingFromData
// ============================================================================

func TestExtractPaddingFromData(t *testing.T) {
	t.Run("ElGamal+DSA (no padding)", func(t *testing.T) {
		d := make([]byte, KEYS_AND_CERT_DATA_SIZE)
		padding := extractPaddingFromData(d, 256, 128)
		assert.Nil(t, padding)
	})

	t.Run("ElGamal+Ed25519 (96 bytes)", func(t *testing.T) {
		d := make([]byte, KEYS_AND_CERT_DATA_SIZE)
		for i := range d {
			d[i] = byte(i)
		}
		padding := extractPaddingFromData(d, 256, 32)
		require.NotNil(t, padding)
		assert.Equal(t, 96, len(padding))
		assert.Equal(t, d[256:352], padding)
	})

	t.Run("X25519+Ed25519 (320 bytes)", func(t *testing.T) {
		d := make([]byte, KEYS_AND_CERT_DATA_SIZE)
		for i := range d {
			d[i] = byte(i)
		}
		padding := extractPaddingFromData(d, 32, 32)
		require.NotNil(t, padding)
		assert.Equal(t, 320, len(padding))
		assert.Equal(t, d[32:256], padding[:224])
		assert.Equal(t, d[256:352], padding[224:])
	})
}

// ============================================================================
// constructSigningKeyFromCert – bounds checks
// ============================================================================

func TestConstructSigningKeyFromCert_LargeKeySize(t *testing.T) {
	keyCert := buildTestKeyCert(t, key_certificate.KEYCERT_SIGN_RSA4096, key_certificate.KEYCERT_CRYPTO_ELG)

	t.Run("RSA4096 returns error not panic", func(t *testing.T) {
		dummyData := make([]byte, KEYS_AND_CERT_DATA_SIZE)
		sigKeySize := keyCert.SigningPublicKeySize() // 512
		assert.Greater(t, sigKeySize, KEYS_AND_CERT_SPK_SIZE)

		_, err := constructSigningKeyFromCert(keyCert, dummyData, sigKeySize)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "exceeds inline capacity")
	})

	t.Run("negative size returns error", func(t *testing.T) {
		dummyData := make([]byte, KEYS_AND_CERT_DATA_SIZE)
		_, err := constructSigningKeyFromCert(keyCert, dummyData, -1)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid signing key size")
	})

	t.Run("zero size returns error", func(t *testing.T) {
		dummyData := make([]byte, KEYS_AND_CERT_DATA_SIZE)
		_, err := constructSigningKeyFromCert(keyCert, dummyData, 0)
		require.Error(t, err)
	})
}

// ============================================================================
// constructPublicKeyFromCert – bounds check
// ============================================================================

func TestConstructPublicKeyFromCert_InsufficientData(t *testing.T) {
	keyCert := buildTestKeyCert(t, key_certificate.KEYCERT_SIGN_ED25519, key_certificate.KEYCERT_CRYPTO_X25519)
	shortData := make([]byte, 100)
	_, err := constructPublicKeyFromCert(keyCert, shortData)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "insufficient data for public key construction")
}

// ============================================================================
// extractElGamalPublicKey / extractEd25519SigningKey
// ============================================================================

func TestExtractElGamalPublicKey_BoundsCheck(t *testing.T) {
	t.Run("valid data", func(t *testing.T) {
		d := make([]byte, 256)
		_, err := rand.Read(d)
		require.NoError(t, err)
		key, err := extractElGamalPublicKey(d, 256)
		require.NoError(t, err)
		assert.Equal(t, 256, key.Len())
	})

	t.Run("insufficient data", func(t *testing.T) {
		d := make([]byte, 100)
		_, err := extractElGamalPublicKey(d, 256)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "insufficient data")
	})
}

func TestExtractEd25519SigningKey_BoundsCheck(t *testing.T) {
	t.Run("valid data", func(t *testing.T) {
		d := make([]byte, 384)
		_, err := rand.Read(d)
		require.NoError(t, err)
		key, err := extractEd25519SigningKey(d, 352, 32)
		require.NoError(t, err)
		assert.Equal(t, 32, key.Len())
	})

	t.Run("offset exceeds data", func(t *testing.T) {
		d := make([]byte, 350)
		_, err := extractEd25519SigningKey(d, 352, 32)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "insufficient data")
	})
}

// ============================================================================
// SignatureSize vs SigningPublicKeySize
// ============================================================================

func TestSignatureSizeVsSigningPublicKeySize(t *testing.T) {
	keyCert := buildTestKeyCert(t, key_certificate.KEYCERT_SIGN_ED25519, key_certificate.KEYCERT_CRYPTO_ELG)

	sigSize := keyCert.SignatureSize()
	spkSize := keyCert.SigningPublicKeySize()

	assert.Equal(t, 64, sigSize, "Ed25519 signature should be 64 bytes")
	assert.Equal(t, 32, spkSize, "Ed25519 signing public key should be 32 bytes")
	assert.NotEqual(t, sigSize, spkSize, "signature size and signing public key size should differ for Ed25519")
}

// ============================================================================
// CryptoSize for MLKEM types
// ============================================================================

func TestCryptoSizeMLKEMTypes(t *testing.T) {
	mlkemTypes := []struct {
		name       string
		cryptoType int
	}{
		{"MLKEM512_X25519", key_certificate.KEYCERT_CRYPTO_MLKEM512_X25519},
		{"MLKEM768_X25519", key_certificate.KEYCERT_CRYPTO_MLKEM768_X25519},
		{"MLKEM1024_X25519", key_certificate.KEYCERT_CRYPTO_MLKEM1024_X25519},
	}
	for _, tt := range mlkemTypes {
		t.Run(tt.name, func(t *testing.T) {
			keyCert := buildTestKeyCert(t, key_certificate.KEYCERT_SIGN_ED25519, tt.cryptoType)
			size := keyCert.CryptoSize()
			assert.Equal(t, 32, size, "MLKEM types should report 32-byte crypto key size")
		})
	}
}

// ============================================================================
// Round-trip tests
// ============================================================================

func TestRoundTripKeysAndCert(t *testing.T) {
	assert := assert.New(t)

	original := createValidKeyAndCert(t)
	assert.True(original.IsValid())

	serialized, err := original.Bytes()
	assert.Nil(err)
	assert.NotEmpty(serialized)

	parsed, remainder, err := ReadKeysAndCert(serialized)
	assert.Nil(err)
	assert.Empty(remainder)
	assert.NotNil(parsed)
	assert.True(parsed.IsValid())

	assert.Equal(original.KeyCertificate.Bytes(), parsed.KeyCertificate.Bytes())
	assert.Equal(original.ReceivingPublic.Bytes(), parsed.ReceivingPublic.Bytes())
	assert.Equal(original.Padding, parsed.Padding)
	assert.Equal(original.SigningPublic.Bytes(), parsed.SigningPublic.Bytes())
}

// ============================================================================
// Interoperability wire format tests
// ============================================================================

func TestInteropWireFormat_X25519Ed25519(t *testing.T) {
	wireData := make([]byte, 384+7)

	cryptoKey := make([]byte, 32)
	for i := range cryptoKey {
		cryptoKey[i] = byte(0xA0 + i)
	}
	copy(wireData[0:32], cryptoKey)

	for i := 32; i < 352; i++ {
		wireData[i] = 0xBB
	}

	sigKey := make([]byte, 32)
	for i := range sigKey {
		sigKey[i] = byte(0xC0 + i)
	}
	copy(wireData[352:384], sigKey)

	wireData[384] = 0x05
	wireData[385] = 0x00
	wireData[386] = 0x04
	wireData[387] = 0x00
	wireData[388] = 0x07 // Ed25519
	wireData[389] = 0x00
	wireData[390] = 0x04 // X25519

	kac, remainder, err := ReadKeysAndCert(wireData)
	require.NoError(t, err, "should parse spec-compliant wire data")
	assert.Empty(t, remainder)

	assert.Equal(t, cryptoKey, kac.ReceivingPublic.Bytes(),
		"crypto key should be start-aligned (bytes 0..31)")
	assert.Equal(t, sigKey, kac.SigningPublic.Bytes(),
		"signing key should be right-justified (bytes 352..383)")

	serialized, err := kac.Bytes()
	require.NoError(t, err)
	assert.Equal(t, wireData, serialized,
		"round-trip serialization must match original wire data exactly")
}

func TestInteropWireFormat_ElGamalEd25519(t *testing.T) {
	wireData := make([]byte, 384+7)

	for i := 0; i < 256; i++ {
		wireData[i] = byte(i)
	}
	for i := 256; i < 352; i++ {
		wireData[i] = 0xDD
	}
	for i := 352; i < 384; i++ {
		wireData[i] = byte(0xE0 + i - 352)
	}

	wireData[384] = 0x05
	wireData[385] = 0x00
	wireData[386] = 0x04
	wireData[387] = 0x00
	wireData[388] = 0x07 // Ed25519
	wireData[389] = 0x00
	wireData[390] = 0x00 // ElGamal

	kac, remainder, err := ReadKeysAndCert(wireData)
	require.NoError(t, err)
	assert.Empty(t, remainder)

	assert.Equal(t, wireData[:256], kac.ReceivingPublic.Bytes())
	assert.Equal(t, wireData[352:384], kac.SigningPublic.Bytes())

	serialized, err := kac.Bytes()
	require.NoError(t, err)
	assert.Equal(t, wireData, serialized)
}

func TestInteropWireFormat_ElGamalDSA(t *testing.T) {
	wireData := make([]byte, 384+3)

	for i := 0; i < 256; i++ {
		wireData[i] = byte(i)
	}
	for i := 256; i < 384; i++ {
		wireData[i] = byte(0xF0 + (i-256)%16)
	}
	wireData[384] = 0x00
	wireData[385] = 0x00
	wireData[386] = 0x00

	kac, remainder, err := ReadKeysAndCert(wireData)
	require.NoError(t, err)
	assert.Empty(t, remainder)

	assert.Equal(t, 256, kac.ReceivingPublic.Len())
	assert.Equal(t, 128, kac.SigningPublic.Len())
	assert.Equal(t, wireData[:256], kac.ReceivingPublic.Bytes())
	assert.Equal(t, wireData[256:384], kac.SigningPublic.Bytes())
}
