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
// Test helpers
// ============================================================================

// buildKeyCertPayload creates a KEY certificate payload for the given key types.
func buildKeyCertPayload(sigType, cryptoType int) []byte {
	payload := make([]byte, 4)
	binary.BigEndian.PutUint16(payload[0:2], uint16(sigType))
	binary.BigEndian.PutUint16(payload[2:4], uint16(cryptoType))
	return payload
}

// buildTestKeyCert creates a KEY certificate for the given types.
func buildTestKeyCert(t *testing.T, sigType, cryptoType int) *key_certificate.KeyCertificate {
	t.Helper()
	payload := buildKeyCertPayload(sigType, cryptoType)
	cert, err := certificate.NewCertificateWithType(certificate.CERT_KEY, payload)
	require.NoError(t, err)
	keyCert, err := key_certificate.KeyCertificateFromCertificate(cert)
	require.NoError(t, err)
	return keyCert
}

// buildX25519Ed25519Data creates a valid 384+cert byte slice for X25519+Ed25519.
func buildX25519Ed25519Data(t *testing.T) []byte {
	t.Helper()
	block := make([]byte, KEYS_AND_CERT_DATA_SIZE) // 384 bytes, zeros

	// Right-justify X25519 key (32 bytes) in 256-byte field
	x25519Key := make([]byte, 32)
	_, err := rand.Read(x25519Key)
	require.NoError(t, err)
	copy(block[KEYS_AND_CERT_PUBKEY_SIZE-32:KEYS_AND_CERT_PUBKEY_SIZE], x25519Key)

	// Right-justify Ed25519 key (32 bytes) in 128-byte field
	ed25519Key := make([]byte, 32)
	_, err = rand.Read(ed25519Key)
	require.NoError(t, err)
	copy(block[KEYS_AND_CERT_DATA_SIZE-32:KEYS_AND_CERT_DATA_SIZE], ed25519Key)

	// Append KEY certificate for X25519+Ed25519
	certPayload := buildKeyCertPayload(key_certificate.KEYCERT_SIGN_ED25519, key_certificate.KEYCERT_CRYPTO_X25519)
	certBytes := []byte{certificate.CERT_KEY}
	lenBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBytes, uint16(len(certPayload)))
	certBytes = append(certBytes, lenBytes...)
	certBytes = append(certBytes, certPayload...)
	return append(block, certBytes...)
}

// buildNullCertData creates a valid 384+3 byte slice for a NULL cert (ElGamal + DSA-SHA1).
func buildNullCertData(t *testing.T) []byte {
	t.Helper()
	block := make([]byte, KEYS_AND_CERT_DATA_SIZE) // 384 bytes

	// Fill ElGamal key region (256 bytes)
	_, err := rand.Read(block[:KEYS_AND_CERT_PUBKEY_SIZE])
	require.NoError(t, err)

	// Fill DSA-SHA1 key region (128 bytes)
	_, err = rand.Read(block[KEYS_AND_CERT_PUBKEY_SIZE:KEYS_AND_CERT_DATA_SIZE])
	require.NoError(t, err)

	// Append NULL certificate: type=0, length=0
	nullCert := []byte{0x00, 0x00, 0x00}
	return append(block, nullCert...)
}

// buildElgEd25519Data builds valid wire data for ElGamal+Ed25519.
func buildElgEd25519Data(t *testing.T) []byte {
	t.Helper()
	block := make([]byte, KEYS_AND_CERT_DATA_SIZE)

	// ElGamal key (256 bytes)
	_, err := rand.Read(block[:256])
	require.NoError(t, err)

	// Padding (96 bytes) + Ed25519 key (32 bytes) in signing field
	_, err = rand.Read(block[256:352]) // padding
	require.NoError(t, err)
	_, err = rand.Read(block[352:384]) // Ed25519 key
	require.NoError(t, err)

	// KEY cert payload for ElGamal+Ed25519
	certPayload := buildKeyCertPayload(key_certificate.KEYCERT_SIGN_ED25519, key_certificate.KEYCERT_CRYPTO_ELG)
	certBytes := []byte{certificate.CERT_KEY}
	lenBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBytes, uint16(len(certPayload)))
	certBytes = append(certBytes, lenBytes...)
	certBytes = append(certBytes, certPayload...)
	return append(block, certBytes...)
}

// ============================================================================
// Critical 1: ReadKeysAndCert works for X25519 crypto type (no panic)
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
		// Read the expected key bytes from the wire data
		expectedCryptoKey := wireData[KEYS_AND_CERT_PUBKEY_SIZE-32 : KEYS_AND_CERT_PUBKEY_SIZE]
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
		// padding = 384 - 32 (X25519) - 32 (Ed25519) = 320
		assert.Equal(t, 320, len(kac.Padding), "padding should be 320 bytes for X25519+Ed25519")
	})
}

// ============================================================================
// Critical 2: constructSigningKeyFromCert bounds check for large signing keys
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
// Critical 3: NULL certificate type support
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

		// The 384-byte block should match
		assert.Equal(t, wireData[:384], serialized[:384], "384-byte block should match")
	})

	t.Run("unsupported cert type returns error", func(t *testing.T) {
		wireData := make([]byte, KEYS_AND_CERT_DATA_SIZE+3)
		wireData[KEYS_AND_CERT_DATA_SIZE] = 0x02 // HIDDEN cert type
		wireData[KEYS_AND_CERT_DATA_SIZE+1] = 0x00
		wireData[KEYS_AND_CERT_DATA_SIZE+2] = 0x00
		_, _, err := ReadKeysAndCert(wireData)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported certificate type")
	})

	t.Run("with remainder", func(t *testing.T) {
		wireData := buildNullCertData(t)
		wireData = append(wireData, 0xAA, 0xBB) // extra bytes
		kac, remainder, err := ReadKeysAndCert(wireData)
		require.NoError(t, err)
		require.NotNil(t, kac)
		assert.Equal(t, []byte{0xAA, 0xBB}, remainder)
	})
}

// ============================================================================
// Critical 4: CryptoSize() for MLKEM types (already fixed in key_certificate)
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
// Gap 1: constructPublicKey supports X25519
// ============================================================================

func TestConstructPublicKey_X25519(t *testing.T) {
	t.Run("valid X25519 key", func(t *testing.T) {
		keyData := make([]byte, 32)
		_, err := rand.Read(keyData)
		require.NoError(t, err)
		pubKey, err := constructPublicKey(keyData, key_certificate.KEYCERT_CRYPTO_X25519)
		require.NoError(t, err)
		assert.NotNil(t, pubKey)
		assert.Equal(t, 32, pubKey.Len())
		assert.Equal(t, keyData, pubKey.Bytes())
	})

	t.Run("wrong size X25519", func(t *testing.T) {
		_, err := constructPublicKey(make([]byte, 64), key_certificate.KEYCERT_CRYPTO_X25519)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid X25519 public key length")
	})

	t.Run("ElGamal still works", func(t *testing.T) {
		keyData := make([]byte, 256)
		pubKey, err := constructPublicKey(keyData, key_certificate.CRYPTO_KEY_TYPE_ELGAMAL)
		require.NoError(t, err)
		assert.Equal(t, 256, pubKey.Len())
	})

	t.Run("unsupported type returns error", func(t *testing.T) {
		_, err := constructPublicKey(make([]byte, 96), 99)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported crypto key type")
	})
}

// ============================================================================
// Gap 2: constructSigningPublicKey supports Ed25519ph and RedDSA
// ============================================================================

func TestConstructSigningPublicKey_ModernTypes(t *testing.T) {
	keyData := make([]byte, 32)
	_, err := rand.Read(keyData)
	require.NoError(t, err)

	t.Run("Ed25519", func(t *testing.T) {
		key, err := constructSigningPublicKey(keyData, key_certificate.SIGNATURE_TYPE_ED25519_SHA512)
		require.NoError(t, err)
		assert.Equal(t, 32, key.Len())
	})

	t.Run("Ed25519ph", func(t *testing.T) {
		key, err := constructSigningPublicKey(keyData, key_certificate.KEYCERT_SIGN_ED25519PH)
		require.NoError(t, err)
		assert.Equal(t, 32, key.Len())
	})

	t.Run("RedDSA", func(t *testing.T) {
		key, err := constructSigningPublicKey(keyData, key_certificate.KEYCERT_SIGN_REDDSA_ED25519)
		require.NoError(t, err)
		assert.Equal(t, 32, key.Len())
	})

	t.Run("unsupported type", func(t *testing.T) {
		_, err := constructSigningPublicKey(keyData, 99)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported signature key type")
	})

	t.Run("wrong size Ed25519", func(t *testing.T) {
		_, err := constructSigningPublicKey(make([]byte, 64), key_certificate.SIGNATURE_TYPE_ED25519_SHA512)
		require.Error(t, err)
	})
}

// ============================================================================
// Gap 3: PrivateKeysAndCert methods
// ============================================================================

func TestPrivateKeysAndCert(t *testing.T) {
	t.Run("nil returns nil keys", func(t *testing.T) {
		var pkac *PrivateKeysAndCert
		assert.Nil(t, pkac.PrivateKey())
		assert.Nil(t, pkac.SigningPrivateKey())
	})

	t.Run("Validate nil struct", func(t *testing.T) {
		var pkac *PrivateKeysAndCert
		err := pkac.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "PrivateKeysAndCert is nil")
	})

	t.Run("Validate missing private key", func(t *testing.T) {
		kac := createValidKeyAndCert(t)
		pkac := &PrivateKeysAndCert{
			KeysAndCert: *kac,
			PK_KEY:      nil,
			SPK_KEY:     []byte("test-spk"),
		}
		err := pkac.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "encryption private key")
	})

	t.Run("Validate missing signing private key", func(t *testing.T) {
		kac := createValidKeyAndCert(t)
		pkac := &PrivateKeysAndCert{
			KeysAndCert: *kac,
			PK_KEY:      []byte("test-pk"),
			SPK_KEY:     nil,
		}
		err := pkac.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "signing private key")
	})

	t.Run("Validate valid struct", func(t *testing.T) {
		kac := createValidKeyAndCert(t)
		pkac := &PrivateKeysAndCert{
			KeysAndCert: *kac,
			PK_KEY:      []byte("test-pk"),
			SPK_KEY:     []byte("test-spk"),
		}
		err := pkac.Validate()
		require.NoError(t, err)
	})

	t.Run("accessor methods return correct values", func(t *testing.T) {
		kac := createValidKeyAndCert(t)
		pkData := []byte("test-private-key")
		spkData := []byte("test-signing-key")
		pkac := &PrivateKeysAndCert{
			KeysAndCert: *kac,
			PK_KEY:      pkData,
			SPK_KEY:     spkData,
		}
		assert.Equal(t, pkData, pkac.PrivateKey().([]byte))
		assert.Equal(t, spkData, pkac.SigningPrivateKey().([]byte))
	})
}

// ============================================================================
// Gap 4: Compressible padding (Proposal 161)
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

// ============================================================================
// Gap 5: ReadKeysAndCertX25519AndEd25519
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
		expectedCrypto := wireData[KEYS_AND_CERT_PUBKEY_SIZE-32 : KEYS_AND_CERT_PUBKEY_SIZE]
		expectedSigning := wireData[KEYS_AND_CERT_DATA_SIZE-32 : KEYS_AND_CERT_DATA_SIZE]

		kac, _, err := ReadKeysAndCertX25519AndEd25519(wireData)
		require.NoError(t, err)
		assert.Equal(t, expectedCrypto, kac.ReceivingPublic.Bytes())
		assert.Equal(t, expectedSigning, kac.SigningPublic.Bytes())
	})

	t.Run("insufficient data", func(t *testing.T) {
		_, _, err := ReadKeysAndCertX25519AndEd25519(make([]byte, 100))
		require.Error(t, err)
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
// Testing Gap 1: X25519 crypto key type test
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
// Testing Gap 3: RSA signing key types (return error, not panic)
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

			// Should return an error, not panic
			_, _, err := ReadKeysAndCert(wireData)
			require.Error(t, err)
		})
	}
}

// ============================================================================
// Testing Gap 4: ECDSA-P384, ECDSA-P521, Ed25519ph, RedDSA signing types
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
			// Fill the signing key region with random data
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
// Testing Gap 5: PrivateKeysAndCert construction test
// ============================================================================

func TestPrivateKeysAndCertConstruction(t *testing.T) {
	kac := createValidKeyAndCert(t)
	pkac := PrivateKeysAndCert{
		KeysAndCert: *kac,
		PK_KEY:      []byte("encryption-private-key"),
		SPK_KEY:     []byte("signing-private-key"),
	}

	assert.NotNil(t, pkac.PK_KEY)
	assert.NotNil(t, pkac.SPK_KEY)
	assert.True(t, pkac.KeysAndCert.IsValid())
}

// ============================================================================
// Testing Gap 6: Malformed certificate data with valid size
// ============================================================================

func TestReadKeysAndCert_MalformedCertData(t *testing.T) {
	t.Run("zero-length KEY cert payload", func(t *testing.T) {
		block := make([]byte, KEYS_AND_CERT_DATA_SIZE)
		// KEY cert with 0 length payload (invalid: needs >= 4 bytes)
		certBytes := []byte{certificate.CERT_KEY, 0x00, 0x00}
		wireData := append(block, certBytes...)
		_, _, err := ReadKeysAndCert(wireData)
		require.Error(t, err)
	})

	t.Run("HASHCASH cert type", func(t *testing.T) {
		block := make([]byte, KEYS_AND_CERT_DATA_SIZE)
		// HASHCASH cert (type 1)
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
}

// ============================================================================
// Quality 1: Tautological checks removed, proper bounds checks added
// ============================================================================

func TestExtractElGamalPublicKey_BoundsCheck(t *testing.T) {
	t.Run("valid data", func(t *testing.T) {
		data := make([]byte, 256)
		_, err := rand.Read(data)
		require.NoError(t, err)
		key, err := extractElGamalPublicKey(data, 256)
		require.NoError(t, err)
		assert.Equal(t, 256, key.Len())
	})

	t.Run("insufficient data", func(t *testing.T) {
		data := make([]byte, 100)
		_, err := extractElGamalPublicKey(data, 256)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "insufficient data")
	})
}

func TestExtractEd25519SigningKey_BoundsCheck(t *testing.T) {
	t.Run("valid data", func(t *testing.T) {
		data := make([]byte, 384)
		_, err := rand.Read(data)
		require.NoError(t, err)
		key, err := extractEd25519SigningKey(data, 352, 32)
		require.NoError(t, err)
		assert.Equal(t, 32, key.Len())
	})

	t.Run("offset exceeds data", func(t *testing.T) {
		data := make([]byte, 350)
		_, err := extractEd25519SigningKey(data, 352, 32)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "insufficient data")
	})
}

// ============================================================================
// Quality 2: SignatureSize() is correctly named (verified via key_certificate)
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
// ElGamal+Ed25519 round-trip with correct wire format
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
// constructPublicKeyFromCert passes full 256-byte region
// ============================================================================

func TestConstructPublicKeyFromCert_InsufficientData(t *testing.T) {
	keyCert := buildTestKeyCert(t, key_certificate.KEYCERT_SIGN_ED25519, key_certificate.KEYCERT_CRYPTO_X25519)
	shortData := make([]byte, 100) // less than 256
	_, err := constructPublicKeyFromCert(keyCert, shortData)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "insufficient data for public key construction")
}

// ============================================================================
// Padding extraction correctness
// ============================================================================

func TestExtractPaddingFromData(t *testing.T) {
	t.Run("ElGamal+DSA (no padding)", func(t *testing.T) {
		data := make([]byte, KEYS_AND_CERT_DATA_SIZE)
		padding := extractPaddingFromData(data, 256, 128) // 384-256-128=0
		assert.Nil(t, padding)
	})

	t.Run("ElGamal+Ed25519 (96 bytes)", func(t *testing.T) {
		data := make([]byte, KEYS_AND_CERT_DATA_SIZE)
		for i := range data {
			data[i] = byte(i)
		}
		padding := extractPaddingFromData(data, 256, 32) // 384-256-32=96
		require.NotNil(t, padding)
		assert.Equal(t, 96, len(padding))
		// For ElGamal (256 bytes), pubPaddingSize=0, sigPaddingSize=96
		// padding = data[256:352]
		assert.Equal(t, data[256:352], padding)
	})

	t.Run("X25519+Ed25519 (320 bytes)", func(t *testing.T) {
		data := make([]byte, KEYS_AND_CERT_DATA_SIZE)
		for i := range data {
			data[i] = byte(i)
		}
		padding := extractPaddingFromData(data, 32, 32) // 384-32-32=320
		require.NotNil(t, padding)
		assert.Equal(t, 320, len(padding))
		// pubPaddingSize=224, sigPaddingSize=96
		// padding[:224] = data[0:224]
		// padding[224:320] = data[256:352]
		assert.Equal(t, data[:224], padding[:224])
		assert.Equal(t, data[256:352], padding[224:])
	})
}

// ============================================================================
// Fuzz test for ReadKeysAndCert
// ============================================================================

func FuzzReadKeysAndCert(f *testing.F) {
	// Seed with valid ElGamal+Ed25519 data
	seed := make([]byte, KEYS_AND_CERT_DATA_SIZE)
	seed = append(seed, []byte{0x05, 0x00, 0x04, 0x00, 0x07, 0x00, 0x00}...)
	f.Add(seed)

	// Seed with NULL cert
	null := make([]byte, KEYS_AND_CERT_DATA_SIZE+3)
	f.Add(null)

	// Seed with short data
	f.Add([]byte{0x00, 0x01, 0x02})

	// Seed with X25519+Ed25519
	x25519Data := make([]byte, KEYS_AND_CERT_DATA_SIZE)
	x25519Data = append(x25519Data, []byte{0x05, 0x00, 0x04, 0x00, 0x07, 0x00, 0x04}...)
	f.Add(x25519Data)

	f.Fuzz(func(t *testing.T, input []byte) {
		// Should never panic, regardless of input
		kac, _, err := ReadKeysAndCert(input)
		if err == nil && kac != nil {
			// If parsing succeeded, Bytes() should not panic
			_, _ = kac.Bytes()
		}
	})
}

// ============================================================================
// Verify existing ElGamal+Ed25519 round-trip via NewKeysAndCert still works
// ============================================================================

func TestNewKeysAndCertElgEd25519_RoundTrip(t *testing.T) {
	// Generate real keys
	ed25519Priv, err := ed25519.GenerateEd25519Key()
	require.NoError(t, err)
	ed25519PubRaw, err := ed25519Priv.Public()
	require.NoError(t, err)
	ed25519Pub, ok := ed25519PubRaw.(interface{ Bytes() []byte })
	require.True(t, ok)

	var elgPub elgamal.ElgPublicKey
	_, err = rand.Read(elgPub[:])
	require.NoError(t, err)

	// Create key certificate
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

	// Calculate padding
	pubKeySize := keyCert.CryptoSize()           // 256
	sigKeySize := keyCert.SigningPublicKeySize() // 32
	paddingSize := KEYS_AND_CERT_DATA_SIZE - pubKeySize - sigKeySize
	padding := make([]byte, paddingSize)
	_, err = rand.Read(padding)
	require.NoError(t, err)

	// Build KeysAndCert
	ed25519PubKey, err := ed25519.NewEd25519PublicKey(ed25519Pub.Bytes())
	require.NoError(t, err)

	kac, err := NewKeysAndCert(keyCert, elgPub, padding, ed25519PubKey)
	require.NoError(t, err)

	// Serialize
	serialized, err := kac.Bytes()
	require.NoError(t, err)

	// Parse back
	parsed, remainder, err := ReadKeysAndCert(serialized)
	require.NoError(t, err)
	assert.Empty(t, remainder)

	// Compare
	assert.Equal(t, kac.ReceivingPublic.Bytes(), parsed.ReceivingPublic.Bytes())
	assert.Equal(t, kac.SigningPublic.Bytes(), parsed.SigningPublic.Bytes())
}
