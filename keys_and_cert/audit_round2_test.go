package keys_and_cert

import (
	"bytes"
	"crypto/rand"
	"sync"
	"testing"

	"github.com/go-i2p/common/certificate"
	"github.com/go-i2p/common/data"
	"github.com/go-i2p/common/key_certificate"
	"github.com/go-i2p/crypto/curve25519"
	"github.com/go-i2p/crypto/ed25519"
	"github.com/go-i2p/crypto/types"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============================================================================
// TEST: Bytes() output size (must be exactly 384 + certLen, minimum 387)
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
// TEST: NewKeysAndCert with X25519+Ed25519 (constructor path)
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

// ============================================================================
// TEST: GenerateCompressiblePadding uniqueness
// ============================================================================

func TestGenerateCompressiblePaddingUniqueness(t *testing.T) {
	const count = 10
	paddings := make([][]byte, count)
	for i := 0; i < count; i++ {
		p, err := GenerateCompressiblePadding(320)
		require.NoError(t, err)
		paddings[i] = p
	}

	// Check that not all paddings are identical (would indicate broken RNG)
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
// TEST: Concurrent access to KeysAndCert
// ============================================================================

func TestKeysAndCertConcurrentAccess(t *testing.T) {
	kac := createValidKeyAndCert(t)

	var wg sync.WaitGroup
	const goroutines = 20

	// Concurrent reads should not race
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = kac.IsValid()
			_, _ = kac.PublicKey()
			_, _ = kac.SigningPublicKey()
			_, _ = kac.Bytes()
			_ = kac.Certificate()
		}()
	}
	wg.Wait()
}

// ============================================================================
// TEST: NULL certificate with DSA-SHA1 key type assertion
// ============================================================================

func TestReadKeysAndCert_NullCertDSAKeyType(t *testing.T) {
	wireData := buildNullCertData(t)
	kac, _, err := ReadKeysAndCert(wireData)
	require.NoError(t, err)

	// The signing key from a NULL cert should be 128 bytes (DSA-SHA1 size)
	assert.Equal(t, 128, kac.SigningPublic.Len(),
		"NULL certificate should produce DSA-SHA1 signing key (128 bytes)")

	// The encryption key should be 256 bytes (ElGamal)
	assert.Equal(t, 256, kac.ReceivingPublic.Len(),
		"NULL certificate should produce ElGamal public key (256 bytes)")

	// The key certificate should report DSA-SHA1 (type 0) and ElGamal (type 0)
	assert.Equal(t, 0, kac.KeyCertificate.SigningPublicKeyType(),
		"NULL cert should report signing type 0 (DSA-SHA1)")
	assert.Equal(t, 0, kac.KeyCertificate.PublicKeyType(),
		"NULL cert should report crypto type 0 (ElGamal)")
}

// ============================================================================
// TEST: Validate checks key sizes against certificate
// ============================================================================

func TestValidateKeySizeMismatch(t *testing.T) {
	t.Run("wrong signing key size", func(t *testing.T) {
		// Create a cert that declares Ed25519 (32 bytes) but attach a 128-byte key
		keyCert := buildTestKeyCert(t, key_certificate.KEYCERT_SIGN_ED25519, key_certificate.KEYCERT_CRYPTO_ELG)
		kac := &KeysAndCert{
			KeyCertificate:  keyCert,
			ReceivingPublic: createDummyReceivingKey(), // 256-byte ElGamal
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
// TEST: NewPrivateKeysAndCert constructor
// ============================================================================

func TestNewPrivateKeysAndCert(t *testing.T) {
	t.Run("creates valid struct with all fields", func(t *testing.T) {
		kac := createValidKeyAndCert(t)
		encPriv := []byte("encryption-private-key")
		sigPriv := []byte("signing-private-key")
		pkac, err := NewPrivateKeysAndCert(
			kac.KeyCertificate,
			kac.ReceivingPublic,
			kac.Padding,
			kac.SigningPublic,
			encPriv,
			sigPriv,
		)
		require.NoError(t, err)
		assert.NotNil(t, pkac)
		assert.Equal(t, encPriv, pkac.PrivateKey().([]byte))
		assert.Equal(t, sigPriv, pkac.SigningPrivateKey().([]byte))
		assert.True(t, pkac.KeysAndCert.IsValid())
	})

	t.Run("rejects nil encryption private key", func(t *testing.T) {
		kac := createValidKeyAndCert(t)
		_, err := NewPrivateKeysAndCert(
			kac.KeyCertificate,
			kac.ReceivingPublic,
			kac.Padding,
			kac.SigningPublic,
			nil,
			[]byte("signing-key"),
		)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "encryption private key")
	})

	t.Run("rejects nil signing private key", func(t *testing.T) {
		kac := createValidKeyAndCert(t)
		_, err := NewPrivateKeysAndCert(
			kac.KeyCertificate,
			kac.ReceivingPublic,
			kac.Padding,
			kac.SigningPublic,
			[]byte("enc-key"),
			nil,
		)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "signing private key")
	})

	t.Run("rejects nil key certificate", func(t *testing.T) {
		_, err := NewPrivateKeysAndCert(
			nil,
			createDummyReceivingKey(),
			make([]byte, 96),
			createDummySigningKey(),
			[]byte("enc-key"),
			[]byte("sig-key"),
		)
		require.Error(t, err)
	})
}

// ============================================================================
// TEST: Interoperability test with known wire data layout
// ============================================================================

func TestInteropWireFormat_X25519Ed25519(t *testing.T) {
	// Construct a wire-format KeysAndCert manually following the I2P spec:
	// - Crypto key (X25519, 32 bytes): START-aligned at offset 0
	// - Padding (224 bytes): after crypto key, offset 32..255
	// - More padding (96 bytes): offset 256..351
	// - Signing key (Ed25519, 32 bytes): RIGHT-justified at offset 352..383
	// - KEY certificate (7 bytes): type=5, len=4, sig_type=0x0007, crypto_type=0x0004
	wireData := make([]byte, 384+7)

	// Known X25519 key bytes (32 bytes at offset 0)
	cryptoKey := make([]byte, 32)
	for i := range cryptoKey {
		cryptoKey[i] = byte(0xA0 + i)
	}
	copy(wireData[0:32], cryptoKey)

	// Known padding (fill with 0xBB)
	for i := 32; i < 352; i++ {
		wireData[i] = 0xBB
	}

	// Known Ed25519 key bytes (32 bytes at offset 352)
	sigKey := make([]byte, 32)
	for i := range sigKey {
		sigKey[i] = byte(0xC0 + i)
	}
	copy(wireData[352:384], sigKey)

	// KEY certificate: type=5, length=4, signing=Ed25519(7), crypto=X25519(4)
	wireData[384] = 0x05 // CERT_KEY
	wireData[385] = 0x00 // length high byte
	wireData[386] = 0x04 // length low byte
	wireData[387] = 0x00 // signing type high byte
	wireData[388] = 0x07 // signing type low byte (Ed25519)
	wireData[389] = 0x00 // crypto type high byte
	wireData[390] = 0x04 // crypto type low byte (X25519)

	kac, remainder, err := ReadKeysAndCert(wireData)
	require.NoError(t, err, "should parse spec-compliant wire data")
	assert.Empty(t, remainder)

	// Verify crypto key is extracted from start-aligned position
	assert.Equal(t, cryptoKey, kac.ReceivingPublic.Bytes(),
		"crypto key should be start-aligned (bytes 0..31)")

	// Verify signing key is extracted from right-justified position
	assert.Equal(t, sigKey, kac.SigningPublic.Bytes(),
		"signing key should be right-justified (bytes 352..383)")

	// Verify round-trip
	serialized, err := kac.Bytes()
	require.NoError(t, err)
	assert.Equal(t, wireData, serialized,
		"round-trip serialization must match original wire data exactly")
}

func TestInteropWireFormat_ElGamalEd25519(t *testing.T) {
	// Construct wire-format for ElGamal(256)+Ed25519(32):
	// - Crypto key (ElGamal, 256 bytes): START-aligned at offset 0 (fills entire field)
	// - Padding (96 bytes): offset 256..351
	// - Signing key (Ed25519, 32 bytes): RIGHT-justified at offset 352..383
	// - KEY certificate
	wireData := make([]byte, 384+7)

	// Known ElGamal key (256 bytes)
	for i := 0; i < 256; i++ {
		wireData[i] = byte(i)
	}
	// Known padding (96 bytes at offset 256)
	for i := 256; i < 352; i++ {
		wireData[i] = 0xDD
	}
	// Known Ed25519 key (32 bytes at offset 352)
	for i := 352; i < 384; i++ {
		wireData[i] = byte(0xE0 + i - 352)
	}

	// KEY certificate: type=5, length=4, signing=Ed25519(7), crypto=ElGamal(0)
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

	// ElGamal fills entire 256-byte field
	assert.Equal(t, wireData[:256], kac.ReceivingPublic.Bytes())
	// Ed25519 is right-justified
	assert.Equal(t, wireData[352:384], kac.SigningPublic.Bytes())

	// Round-trip
	serialized, err := kac.Bytes()
	require.NoError(t, err)
	assert.Equal(t, wireData, serialized)
}

func TestInteropWireFormat_ElGamalDSA(t *testing.T) {
	// Construct wire-format for NULL cert (ElGamal+DSA-SHA1):
	// - Crypto key (ElGamal, 256 bytes): offset 0..255
	// - Signing key (DSA-SHA1, 128 bytes): offset 256..383 (fills entire signing field)
	// - NULL certificate (3 bytes): type=0, len=0
	wireData := make([]byte, 384+3)

	for i := 0; i < 256; i++ {
		wireData[i] = byte(i)
	}
	for i := 256; i < 384; i++ {
		wireData[i] = byte(0xF0 + (i-256)%16)
	}
	// NULL cert
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

// ============================================================================
// TEST: Padding consistency between ReadKeysAndCertElgAndEd25519 and ReadKeysAndCert
// ============================================================================

func TestPaddingConsistencyBetweenReadPaths(t *testing.T) {
	wireData := buildElgEd25519Data(t)

	// Parse with generic path
	kac1, _, err := ReadKeysAndCert(wireData)
	require.NoError(t, err)

	// Parse with specialized path
	kac2, _, err := ReadKeysAndCertElgAndEd25519(wireData)
	require.NoError(t, err)

	// Both should produce identical padding
	assert.Equal(t, kac1.Padding, kac2.Padding,
		"generic and specialized read paths should produce identical padding")
}

// ============================================================================
// Helpers
// ============================================================================

// createX25519Ed25519KeysAndCert creates a KeysAndCert with X25519 crypto + Ed25519 signing
// using the NewKeysAndCert constructor path.
func createX25519Ed25519KeysAndCert(t *testing.T) *KeysAndCert {
	t.Helper()

	// Generate Ed25519 signing key
	ed25519Priv, err := ed25519.GenerateEd25519Key()
	require.NoError(t, err)
	ed25519PubRaw, err := ed25519Priv.Public()
	require.NoError(t, err)
	ed25519Pub, ok := ed25519PubRaw.(types.SigningPublicKey)
	require.True(t, ok)

	// Generate X25519 key
	x25519Key := make(curve25519.Curve25519PublicKey, 32)
	_, err = rand.Read(x25519Key)
	require.NoError(t, err)

	// Create key certificate for X25519+Ed25519
	var payload bytes.Buffer
	sigType, err := data.NewIntegerFromInt(key_certificate.KEYCERT_SIGN_ED25519, 2)
	require.NoError(t, err)
	cryptoType, err := data.NewIntegerFromInt(key_certificate.KEYCERT_CRYPTO_X25519, 2)
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

	kac, err := NewKeysAndCert(keyCert, x25519Key, padding, ed25519Pub)
	require.NoError(t, err)

	return kac
}

// createWrongSizeSigningKey creates a 64-byte signing key that
// would be wrong for a certificate declaring Ed25519 (32 bytes).
func createWrongSizeSigningKey() types.SigningPublicKey {
	return wrongSizeKey(make([]byte, 64))
}

// wrongSizeKey implements types.SigningPublicKey with arbitrary size for testing.
type wrongSizeKey []byte

func (k wrongSizeKey) Bytes() []byte                        { return []byte(k) }
func (k wrongSizeKey) Len() int                             { return len(k) }
func (k wrongSizeKey) NewVerifier() (types.Verifier, error) { return nil, nil }
