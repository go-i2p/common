package key_certificate

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSigningPublicKeyTypeReturnsCorrectInteger(t *testing.T) {
	assert := assert.New(t)

	key_cert, _, err := NewKeyCertificate(testKeyCertBytesP521Signing)
	assert.Nil(err)

	pk_type := key_cert.SigningPublicKeyType()
	assert.Equal(KEYCERT_SIGN_P521, pk_type, "SigningPublicKeyType() did not return correct type")
}

func TestPublicKeyTypeReturnsCorrectInteger(t *testing.T) {
	assert := assert.New(t)

	key_cert, _, err := NewKeyCertificate(testKeyCertBytesDSAElGamal)
	assert.Nil(err)

	pk_type := key_cert.PublicKeyType()
	assert.Equal(KEYCERT_CRYPTO_ELG, pk_type, "PublicKeyType() did not return correct type")
}

func TestConstructPublicKeyReturnsCorrectDataWithElg(t *testing.T) {
	assert := assert.New(t)

	key_cert, _, err := NewKeyCertificate(testKeyCertBytesDSAElGamal)
	data := make([]byte, 256)
	pk, err := key_cert.ConstructPublicKey(data)

	assert.Nil(err, "ConstructPublicKey() returned error with valid data")
	assert.Equal(pk.Len(), 256, "ConstructPublicKey() did not return public key with correct length")
}

// TestConstructPublicKey_X25519_StartAligned verifies that ConstructPublicKey
// extracts X25519 key from the start of the 256-byte field (bytes 0–31),
// not from the end (bytes 224–255).
func TestConstructPublicKey_X25519_StartAligned(t *testing.T) {
	keyCert, err := NewKeyCertificateWithTypes(KEYCERT_SIGN_ED25519, KEYCERT_CRYPTO_X25519)
	require.NoError(t, err)

	// Create 256-byte data with distinct pattern at the start and zeros elsewhere
	data := make([]byte, KEYCERT_PUBKEY_SIZE)
	for i := 0; i < KEYCERT_CRYPTO_X25519_SIZE; i++ {
		data[i] = byte(i + 1) // bytes 0–31 have non-zero pattern
	}

	pk, err := keyCert.ConstructPublicKey(data)
	require.NoError(t, err)
	require.NotNil(t, pk)

	assert.Equal(t, KEYCERT_CRYPTO_X25519_SIZE, pk.Len(),
		"X25519 public key should be 32 bytes")

	pkBytes := pk.Bytes()
	assert.Equal(t, byte(1), pkBytes[0],
		"First byte should be 0x01 (from start-aligned position)")
	assert.Equal(t, byte(32), pkBytes[31],
		"Last byte should be 0x20 (byte 31 from start)")
}

// TestConstructPublicKey_MLKEM_Types verifies that MLKEM hybrid types
// (which use X25519 as the base) are handled correctly.
func TestConstructPublicKey_MLKEM_Types(t *testing.T) {
	mlkemTypes := []struct {
		name       string
		cryptoType int
	}{
		{"MLKEM512_X25519", KEYCERT_CRYPTO_MLKEM512_X25519},
		{"MLKEM768_X25519", KEYCERT_CRYPTO_MLKEM768_X25519},
		{"MLKEM1024_X25519", KEYCERT_CRYPTO_MLKEM1024_X25519},
	}

	for _, tt := range mlkemTypes {
		t.Run(tt.name, func(t *testing.T) {
			keyCert, err := NewKeyCertificateWithTypes(KEYCERT_SIGN_ED25519, tt.cryptoType)
			require.NoError(t, err)

			data := make([]byte, KEYCERT_PUBKEY_SIZE)
			for i := 0; i < 32; i++ {
				data[i] = byte(i + 0xA0)
			}

			pk, err := keyCert.ConstructPublicKey(data)
			require.NoError(t, err)
			require.NotNil(t, pk)
			assert.Equal(t, KEYCERT_CRYPTO_X25519_SIZE, pk.Len())
			assert.Equal(t, byte(0xA0), pk.Bytes()[0])
		})
	}
}

func TestConstructSigningPublicKeyWithDSASHA1(t *testing.T) {
	assert := assert.New(t)

	key_cert, _, err := NewKeyCertificate(testKeyCertBytesDSAElGamal)
	data := make([]byte, 128)
	spk, err := key_cert.ConstructSigningPublicKey(data)

	assert.Nil(err, "ConstructSigningPublicKey() with DSA SHA1 returned error with valid data")
	assert.Equal(spk.Len(), KEYCERT_SIGN_DSA_SHA1_SIZE, "ConstructSigningPublicKey() with DSA SHA1 returned incorrect signingPublicKey length")
}

func TestConstructSigningPublicKeyWithP256(t *testing.T) {
	assert := assert.New(t)

	key_cert, _, err := NewKeyCertificate(testKeyCertBytesP256P256)
	data := make([]byte, 128)
	spk, err := key_cert.ConstructSigningPublicKey(data)

	assert.Nil(err, "ConstructSigningPublicKey() with P256 returned err on valid data")
	assert.Equal(spk.Len(), KEYCERT_SIGN_P256_SIZE, "ConstructSigningPublicKey() with P256 returned incorrect signingPublicKey length")
}

func TestConstructSigningPublicKeyWithP384(t *testing.T) {
	assert := assert.New(t)

	key_cert, _, err := NewKeyCertificate(testKeyCertBytesP384P384)
	data := make([]byte, 128)
	spk, err := key_cert.ConstructSigningPublicKey(data)

	assert.Nil(err, "ConstructSigningPublicKey() with P384 returned err on valid data")
	assert.Equal(spk.Len(), KEYCERT_SIGN_P384_SIZE, "ConstructSigningPublicKey() with P384 returned incorrect signingPublicKey length")
}

// TestConstructSigningPublicKey_DSA_NonZeroData tests DSA key construction
// with non-zero data patterns to verify correct byte extraction from the padded field.
func TestConstructSigningPublicKey_DSA_NonZeroData(t *testing.T) {
	keyCert, err := NewKeyCertificateWithTypes(KEYCERT_SIGN_DSA_SHA1, KEYCERT_CRYPTO_ELG)
	require.NoError(t, err)

	data := makeTestBytes(KEYCERT_SPK_SIZE, 1)

	spk, err := keyCert.ConstructSigningPublicKey(data)
	require.NoError(t, err)
	require.NotNil(t, spk)
	assert.Equal(t, KEYCERT_SIGN_DSA_SHA1_SIZE, spk.Len())

	spkBytes := spk.Bytes()
	assert.NotEqual(t, make([]byte, KEYCERT_SIGN_DSA_SHA1_SIZE), spkBytes,
		"DSA key bytes should not be all zeros when input has non-zero data")
}

// TestConstructSigningPublicKey_Ed25519ViaKeyCertificate verifies the Ed25519 construction
// path through ConstructSigningPublicKey on a KeyCertificate object.
func TestConstructSigningPublicKey_Ed25519ViaKeyCertificate(t *testing.T) {
	keyCert, err := NewKeyCertificateWithTypes(KEYCERT_SIGN_ED25519, KEYCERT_CRYPTO_X25519)
	require.NoError(t, err)

	keyData := makeTestBytes(KEYCERT_SIGN_ED25519_SIZE, 1)

	spk, err := keyCert.ConstructSigningPublicKey(keyData)
	require.NoError(t, err)
	require.NotNil(t, spk)
	assert.Equal(t, KEYCERT_SIGN_ED25519_SIZE, spk.Len())
}

// TestConstructSigningPublicKey_RedDSAViaKeyCertificate verifies RedDSA construction.
func TestConstructSigningPublicKey_RedDSAViaKeyCertificate(t *testing.T) {
	keyCert, err := NewKeyCertificateWithTypes(KEYCERT_SIGN_REDDSA_ED25519, KEYCERT_CRYPTO_X25519)
	require.NoError(t, err)

	keyData := makeTestBytes(KEYCERT_SIGN_ED25519_SIZE, 1)

	spk, err := keyCert.ConstructSigningPublicKey(keyData)
	require.NoError(t, err)
	require.NotNil(t, spk)
	assert.Equal(t, KEYCERT_SIGN_ED25519_SIZE, spk.Len())
}

// TestSignatureSize_ReturnsActualSignatureSizes verifies that SignatureSize()
// returns actual signature sizes (not signing public key sizes).
func TestSignatureSize_ReturnsActualSignatureSizes(t *testing.T) {
	tests := []struct {
		name        string
		signingType int
		cryptoType  int
		wantSigSize int
	}{
		{"DSA_SHA1", KEYCERT_SIGN_DSA_SHA1, KEYCERT_CRYPTO_ELG, 40},
		{"P256", KEYCERT_SIGN_P256, KEYCERT_CRYPTO_ELG, 64},
		{"P384", KEYCERT_SIGN_P384, KEYCERT_CRYPTO_ELG, 96},
		{"P521", KEYCERT_SIGN_P521, KEYCERT_CRYPTO_ELG, 132},
		{"RSA2048", KEYCERT_SIGN_RSA2048, KEYCERT_CRYPTO_ELG, 256},
		{"RSA3072", KEYCERT_SIGN_RSA3072, KEYCERT_CRYPTO_ELG, 384},
		{"RSA4096", KEYCERT_SIGN_RSA4096, KEYCERT_CRYPTO_ELG, 512},
		{"Ed25519", KEYCERT_SIGN_ED25519, KEYCERT_CRYPTO_X25519, 64},
		{"Ed25519ph", KEYCERT_SIGN_ED25519PH, KEYCERT_CRYPTO_X25519, 64},
		{"RedDSA", KEYCERT_SIGN_REDDSA_ED25519, KEYCERT_CRYPTO_X25519, 64},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyCert, err := NewKeyCertificateWithTypes(tt.signingType, tt.cryptoType)
			require.NoError(t, err)
			require.NotNil(t, keyCert)

			sigSize := keyCert.SignatureSize()
			assert.Equal(t, tt.wantSigSize, sigSize,
				"SignatureSize() should return actual signature size, not signing public key size")
		})
	}
}

// TestCryptoSize_AllSpecTypes verifies CryptoSize() works for all spec-defined types.
func TestCryptoSize_AllSpecTypes(t *testing.T) {
	tests := []struct {
		name       string
		cryptoType int
		wantSize   int
	}{
		{"ElGamal", KEYCERT_CRYPTO_ELG, 256},
		{"P256", KEYCERT_CRYPTO_P256, 64},
		{"P384", KEYCERT_CRYPTO_P384, 96},
		{"P521", KEYCERT_CRYPTO_P521, 132},
		{"X25519", KEYCERT_CRYPTO_X25519, 32},
		{"MLKEM512_X25519", KEYCERT_CRYPTO_MLKEM512_X25519, 32},
		{"MLKEM768_X25519", KEYCERT_CRYPTO_MLKEM768_X25519, 32},
		{"MLKEM1024_X25519", KEYCERT_CRYPTO_MLKEM1024_X25519, 32},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyCert, err := NewKeyCertificateWithTypes(KEYCERT_SIGN_ED25519, tt.cryptoType)
			require.NoError(t, err)

			size := keyCert.CryptoSize()
			assert.Equal(t, tt.wantSize, size)
		})
	}
}

// TestSigningPublicKeySize_AllTypes verifies SigningPublicKeySize() includes all spec types.
func TestSigningPublicKeySize_AllTypes(t *testing.T) {
	tests := []struct {
		name        string
		signingType int
		cryptoType  int
		wantSize    int
	}{
		{"DSA_SHA1", KEYCERT_SIGN_DSA_SHA1, KEYCERT_CRYPTO_ELG, 128},
		{"P256", KEYCERT_SIGN_P256, KEYCERT_CRYPTO_ELG, 64},
		{"P384", KEYCERT_SIGN_P384, KEYCERT_CRYPTO_ELG, 96},
		{"P521", KEYCERT_SIGN_P521, KEYCERT_CRYPTO_ELG, 132},
		{"RSA2048", KEYCERT_SIGN_RSA2048, KEYCERT_CRYPTO_ELG, 256},
		{"RSA3072", KEYCERT_SIGN_RSA3072, KEYCERT_CRYPTO_ELG, 384},
		{"RSA4096", KEYCERT_SIGN_RSA4096, KEYCERT_CRYPTO_ELG, 512},
		{"Ed25519", KEYCERT_SIGN_ED25519, KEYCERT_CRYPTO_X25519, 32},
		{"Ed25519ph", KEYCERT_SIGN_ED25519PH, KEYCERT_CRYPTO_X25519, 32},
		{"RedDSA", KEYCERT_SIGN_REDDSA_ED25519, KEYCERT_CRYPTO_X25519, 32},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyCert, err := NewKeyCertificateWithTypes(tt.signingType, tt.cryptoType)
			require.NoError(t, err)

			size := keyCert.SigningPublicKeySize()
			assert.Equal(t, tt.wantSize, size)
		})
	}
}

// TestNewKeyCertificate_ExcessTrailingData verifies that the remainder
// return value correctly captures bytes after the certificate.
func TestNewKeyCertificate_ExcessTrailingData(t *testing.T) {
	keyCert, remainder, err := NewKeyCertificate(testKeyCertBytesWithTrailing)
	require.NoError(t, err)
	require.NotNil(t, keyCert)

	assert.Equal(t, KEYCERT_SIGN_ED25519, keyCert.SigningPublicKeyType())
	assert.Equal(t, KEYCERT_CRYPTO_X25519, keyCert.PublicKeyType())

	require.Len(t, remainder, 3, "Should have 3 remainder bytes")
	assert.Equal(t, byte(0xAA), remainder[0])
	assert.Equal(t, byte(0xBB), remainder[1])
	assert.Equal(t, byte(0xCC), remainder[2])
}
