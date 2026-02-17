package key_certificate

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSignatureSize_ReturnsActualSignatureSizes verifies that SignatureSize()
// returns actual signature sizes (not signing public key sizes).
// This was a critical bug: Ed25519 returned 32 (pubkey size) instead of 64 (sig size).
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

// TestSignatureSize_ConsistentWithGetSignatureSize verifies that the method
// and the standalone function return identical values for all key types.
func TestSignatureSize_ConsistentWithGetSignatureSize(t *testing.T) {
	sigTypes := []int{
		KEYCERT_SIGN_DSA_SHA1,
		KEYCERT_SIGN_P256,
		KEYCERT_SIGN_P384,
		KEYCERT_SIGN_P521,
		KEYCERT_SIGN_RSA2048,
		KEYCERT_SIGN_RSA3072,
		KEYCERT_SIGN_RSA4096,
		KEYCERT_SIGN_ED25519,
		KEYCERT_SIGN_ED25519PH,
		KEYCERT_SIGN_REDDSA_ED25519,
	}

	for _, sigType := range sigTypes {
		keyCert, err := NewKeyCertificateWithTypes(sigType, KEYCERT_CRYPTO_X25519)
		require.NoError(t, err)

		methodSize := keyCert.SignatureSize()
		funcSize, err := GetSignatureSize(sigType)
		require.NoError(t, err)

		assert.Equal(t, funcSize, methodSize,
			"SignatureSize() method and GetSignatureSize() function should return same value for type %d", sigType)
	}
}

// TestCryptoSize_AllSpecTypes verifies CryptoSize() works for all spec-defined types
// including MLKEM hybrid types that were previously missing.
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

// TestCryptoSize_UnknownTypeReturnsZero verifies CryptoSize() returns 0 for unknown types.
func TestCryptoSize_UnknownTypeReturnsZero(t *testing.T) {
	// Create with valid type, then manually alter
	keyCert := &KeyCertificate{}
	keyCert.CpkType = []byte{0x03, 0xe8} // type 1000 - unknown

	size := keyCert.CryptoSize()
	assert.Equal(t, 0, size, "CryptoSize() should return 0 for unknown crypto type")
}

// TestSelectSigningKeyConstructor_NoPanicOnP521 verifies P521 returns error, not panic.
func TestSelectSigningKeyConstructor_NoPanicOnP521(t *testing.T) {
	data := make([]byte, 132) // P521 key size
	key, err := selectSigningKeyConstructor(KEYCERT_SIGN_P521, data)
	assert.Error(t, err, "P521 should return error, not panic")
	assert.Nil(t, key)
	assert.Contains(t, err.Error(), "unimplemented")
}

// TestSelectSigningKeyConstructor_NoPanicOnRSA verifies RSA types return error, not panic.
func TestSelectSigningKeyConstructor_NoPanicOnRSA(t *testing.T) {
	rsaTypes := []struct {
		name    string
		keyType int
		size    int
	}{
		{"RSA2048", KEYCERT_SIGN_RSA2048, 256},
		{"RSA3072", KEYCERT_SIGN_RSA3072, 384},
		{"RSA4096", KEYCERT_SIGN_RSA4096, 512},
	}

	for _, tt := range rsaTypes {
		t.Run(tt.name, func(t *testing.T) {
			data := make([]byte, tt.size)
			key, err := selectSigningKeyConstructor(tt.keyType, data)
			assert.Error(t, err, "%s should return error, not panic", tt.name)
			assert.Nil(t, key)
			assert.Contains(t, err.Error(), "unimplemented")
		})
	}
}

// TestConstructPublicKey_UnknownTypeReturnsError verifies unknown crypto types get an error.
func TestConstructPublicKey_UnknownTypeReturnsError(t *testing.T) {
	// Create certificate with P256 crypto type (valid but unimplemented construction)
	keyCert, err := NewKeyCertificateWithTypes(KEYCERT_SIGN_ED25519, KEYCERT_CRYPTO_P256)
	require.NoError(t, err)

	data := make([]byte, 256) // Sufficient data
	pk, err := keyCert.ConstructPublicKey(data)
	assert.Error(t, err, "ConstructPublicKey should return error for unsupported type")
	assert.Nil(t, pk)
}

// TestConstructSigningPublicKeyByType_RawEd25519 verifies Ed25519 construction from raw 32-byte key.
func TestConstructSigningPublicKeyByType_RawEd25519(t *testing.T) {
	rawKey := make([]byte, 32)
	for i := range rawKey {
		rawKey[i] = byte(i)
	}

	spk, err := ConstructSigningPublicKeyByType(rawKey, KEYCERT_SIGN_ED25519)
	require.NoError(t, err)
	require.NotNil(t, spk)
	assert.Equal(t, 32, spk.Len())
}

// TestConstructSigningPublicKeyByType_RawP256 verifies P256 construction from raw 64-byte key.
func TestConstructSigningPublicKeyByType_RawP256(t *testing.T) {
	rawKey := make([]byte, 64)
	for i := range rawKey {
		rawKey[i] = byte(i)
	}

	spk, err := ConstructSigningPublicKeyByType(rawKey, KEYCERT_SIGN_P256)
	require.NoError(t, err)
	require.NotNil(t, spk)
	assert.Equal(t, KEYCERT_SIGN_P256_SIZE, spk.Len())
}

// TestConstructSigningPublicKeyByType_RawP384 verifies P384 construction from raw 96-byte key.
func TestConstructSigningPublicKeyByType_RawP384(t *testing.T) {
	rawKey := make([]byte, 96)
	for i := range rawKey {
		rawKey[i] = byte(i)
	}

	spk, err := ConstructSigningPublicKeyByType(rawKey, KEYCERT_SIGN_P384)
	require.NoError(t, err)
	require.NotNil(t, spk)
	assert.Equal(t, KEYCERT_SIGN_P384_SIZE, spk.Len())
}

// TestConstructSigningPublicKeyByType_InsufficientData verifies bounds checking.
func TestConstructSigningPublicKeyByType_InsufficientData(t *testing.T) {
	tests := []struct {
		name    string
		sigType int
		dataLen int
	}{
		{"P256_TooShort", KEYCERT_SIGN_P256, 32},
		{"P384_TooShort", KEYCERT_SIGN_P384, 48},
		{"DSA_TooShort", KEYCERT_SIGN_DSA_SHA1, 64},
		{"Ed25519_TooShort", KEYCERT_SIGN_ED25519, 16},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := make([]byte, tt.dataLen)
			spk, err := ConstructSigningPublicKeyByType(data, tt.sigType)
			assert.Error(t, err, "Should return error for insufficient data")
			assert.Nil(t, spk)
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

// TestConstructSigningPublicKey_Ed25519ViaKeyCertificate verifies the Ed25519 construction
// path through ConstructSigningPublicKey on a KeyCertificate object.
func TestConstructSigningPublicKey_Ed25519ViaKeyCertificate(t *testing.T) {
	keyCert, err := NewKeyCertificateWithTypes(KEYCERT_SIGN_ED25519, KEYCERT_CRYPTO_X25519)
	require.NoError(t, err)

	// Ed25519 expects exactly 32 bytes of raw key data
	keyData := make([]byte, KEYCERT_SIGN_ED25519_SIZE)
	for i := range keyData {
		keyData[i] = byte(i + 1)
	}

	spk, err := keyCert.ConstructSigningPublicKey(keyData)
	require.NoError(t, err)
	require.NotNil(t, spk)
	assert.Equal(t, KEYCERT_SIGN_ED25519_SIZE, spk.Len())
}

// TestConstructSigningPublicKey_RedDSAViaKeyCertificate verifies RedDSA construction.
func TestConstructSigningPublicKey_RedDSAViaKeyCertificate(t *testing.T) {
	keyCert, err := NewKeyCertificateWithTypes(KEYCERT_SIGN_REDDSA_ED25519, KEYCERT_CRYPTO_X25519)
	require.NoError(t, err)

	keyData := make([]byte, KEYCERT_SIGN_ED25519_SIZE)
	for i := range keyData {
		keyData[i] = byte(i + 1)
	}

	spk, err := keyCert.ConstructSigningPublicKey(keyData)
	require.NoError(t, err)
	require.NotNil(t, spk)
	assert.Equal(t, KEYCERT_SIGN_ED25519_SIZE, spk.Len())
}
