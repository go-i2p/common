package key_certificate

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-i2p/common/certificate"
)

func TestSigningPublicKeyTypeWithInvalidData(t *testing.T) {
	assert := assert.New(t)

	key_cert, _, err := NewKeyCertificate(testKeyCertBytesShortPayload)
	assert.NotNil(err)
	assert.Contains(err.Error(), "key certificate data too short")
	assert.Nil(key_cert)
}

func TestPublicKeyTypeWithInvalidData(t *testing.T) {
	assert := assert.New(t)

	key_cert, _, err := NewKeyCertificate(testKeyCertBytesShortCert)
	assert.NotNil(err)
	assert.Contains(err.Error(), "certificate parsing warning: certificate data is shorter than specified by length", "Expected error for invalid data")
	assert.Nil(key_cert)
}

func TestConstructPublicKeyWithInsufficientData(t *testing.T) {
	assert := assert.New(t)

	key_cert, _, err := NewKeyCertificate(testKeyCertBytesDSAElGamal)
	assert.Nil(err)

	data := make([]byte, 255) // ELG requires 256 bytes
	_, err = key_cert.ConstructPublicKey(data)

	assert.NotNil(err)
	assert.Equal("error constructing public key: not enough data", err.Error())
}

// TestConstructPublicKey_BoundsCheck verifies that ConstructPublicKey requires
// KEYCERT_PUBKEY_SIZE (256) bytes regardless of crypto type.
func TestConstructPublicKey_BoundsCheck(t *testing.T) {
	keyCert, err := NewKeyCertificateWithTypes(KEYCERT_SIGN_ED25519, KEYCERT_CRYPTO_X25519)
	require.NoError(t, err)

	tests := []struct {
		name    string
		dataLen int
		wantErr bool
	}{
		{"exactly_32_bytes", 32, true}, // CryptoSize but not KEYCERT_PUBKEY_SIZE
		{"255_bytes", 255, true},       // One short
		{"256_bytes", 256, false},      // Exactly right
		{"300_bytes", 300, false},      // Extra is OK
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := make([]byte, tt.dataLen)
			_, err := keyCert.ConstructPublicKey(data)
			if tt.wantErr {
				assert.Error(t, err, "Should reject data shorter than KEYCERT_PUBKEY_SIZE")
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestConstructPublicKey_X25519_NotEndAligned confirms the old bug is fixed:
// if key material is only at the end of the 256-byte field, the extracted key
// should be all zeros (since we now read from the start).
func TestConstructPublicKey_X25519_NotEndAligned(t *testing.T) {
	keyCert, err := NewKeyCertificateWithTypes(KEYCERT_SIGN_ED25519, KEYCERT_CRYPTO_X25519)
	require.NoError(t, err)

	data := make([]byte, KEYCERT_PUBKEY_SIZE)
	for i := KEYCERT_PUBKEY_SIZE - KEYCERT_CRYPTO_X25519_SIZE; i < KEYCERT_PUBKEY_SIZE; i++ {
		data[i] = byte(i - (KEYCERT_PUBKEY_SIZE - KEYCERT_CRYPTO_X25519_SIZE) + 1)
	}

	pk, err := keyCert.ConstructPublicKey(data)
	require.NoError(t, err)

	pkBytes := pk.Bytes()
	for i := 0; i < KEYCERT_CRYPTO_X25519_SIZE; i++ {
		assert.Equal(t, byte(0), pkBytes[i],
			"Key extracted from start should be zero when data is only at end")
	}
}

// TestConstructPublicKey_UnknownTypeReturnsError verifies unknown crypto types get an error.
func TestConstructPublicKey_UnknownTypeReturnsError(t *testing.T) {
	keyCert, err := NewKeyCertificateWithTypes(KEYCERT_SIGN_ED25519, KEYCERT_CRYPTO_P256)
	require.NoError(t, err)

	data := make([]byte, 256)
	pk, err := keyCert.ConstructPublicKey(data)
	assert.Error(t, err, "ConstructPublicKey should return error for unsupported type")
	assert.Nil(t, pk)
}

// TestCryptoSize_UnknownTypeReturnsZero verifies CryptoSize() returns 0 for unknown types.
func TestCryptoSize_UnknownTypeReturnsZero(t *testing.T) {
	keyCert := &KeyCertificate{}
	keyCert.CpkType = testUnknownTypeBytes

	size := keyCert.CryptoSize()
	assert.Equal(t, 0, size, "CryptoSize() should return 0 for unknown crypto type")
}

// TestSigningPublicKeySize_UnknownTypeReturnsZero verifies that unknown signing
// types return 0 instead of the legacy 128-byte fallback.
func TestSigningPublicKeySize_UnknownTypeReturnsZero(t *testing.T) {
	keyCert := &KeyCertificate{}
	keyCert.SpkType = testUnknownTypeBytes

	size := keyCert.SigningPublicKeySize()
	assert.Equal(t, 0, size,
		"SigningPublicKeySize should return 0 for unknown types, not 128")
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

func TestConstructSigningPublicKeyReportsWhenDataTooSmall(t *testing.T) {
	assert := assert.New(t)

	key_cert, _, err := NewKeyCertificate(testKeyCertBytesDSAElGamal)
	data := make([]byte, 127)
	_, err = key_cert.ConstructSigningPublicKey(data)

	if assert.NotNil(err) {
		assert.Equal("error constructing signing public key: not enough data", err.Error(), "correct error message should be returned")
	}
}

// TestValidatePayloadLengthAgainstKeyTypes verifies the payload validation.
func TestValidatePayloadLengthAgainstKeyTypes(t *testing.T) {
	tests := []struct {
		name    string
		sigType int
		cryType int
		dataLen int
		wantErr bool
	}{
		{"Ed25519_X25519_exact", KEYCERT_SIGN_ED25519, KEYCERT_CRYPTO_X25519, 4, false},
		{"DSA_ElGamal_exact", KEYCERT_SIGN_DSA_SHA1, KEYCERT_CRYPTO_ELG, 4, false},
		{"P521_ElGamal_short", KEYCERT_SIGN_P521, KEYCERT_CRYPTO_ELG, 4, true},
		{"P521_ElGamal_enough", KEYCERT_SIGN_P521, KEYCERT_CRYPTO_ELG, 8, false},
		{"RSA2048_ElGamal_short", KEYCERT_SIGN_RSA2048, KEYCERT_CRYPTO_ELG, 4, true},
		{"RSA2048_ElGamal_enough", KEYCERT_SIGN_RSA2048, KEYCERT_CRYPTO_ELG, 132, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spkType := make([]byte, 2)
			spkType[0] = byte(tt.sigType >> 8)
			spkType[1] = byte(tt.sigType & 0xFF)

			cpkType := make([]byte, 2)
			cpkType[0] = byte(tt.cryType >> 8)
			cpkType[1] = byte(tt.cryType & 0xFF)

			certData := make([]byte, tt.dataLen)

			err := validatePayloadLengthAgainstKeyTypes(certData, spkType, cpkType)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestKeyCertificateFromCertificate_NonKeyCertificateType verifies that
// KeyCertificateFromCertificate returns an error for non-KEY certificate types.
func TestKeyCertificateFromCertificate_NonKeyCertificateType(t *testing.T) {
	tests := []struct {
		name     string
		certType byte
	}{
		{"NULL", certificate.CERT_NULL},
		{"HASHCASH", certificate.CERT_HASHCASH},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rawBytes := []byte{tt.certType, 0x00, 0x00}
			cert, _, err := certificate.ReadCertificate(rawBytes)
			require.NoError(t, err)

			keyCert, err := KeyCertificateFromCertificate(cert)
			assert.Error(t, err, "Should reject non-KEY certificate type %d", tt.certType)
			assert.Nil(t, keyCert)
			assert.Contains(t, err.Error(), "invalid certificate type")
		})
	}
}
