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
	assert.Contains(err.Error(), "too short")
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
	// Inject a key certificate with crypto type 200 (truly unknown) via raw payload.
	payload := []byte{0x00, 0x07, 0x00, 0xC8} // signing=Ed25519(7), crypto=200
	cert, err := certificate.NewCertificateWithType(certificate.CERT_KEY, payload)
	require.NoError(t, err)
	keyCert, err := KeyCertificateFromCertificate(cert)
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

// TestSelectSigningKeyConstructor_P521Constructs verifies P521 now succeeds with valid data.
func TestSelectSigningKeyConstructor_P521Constructs(t *testing.T) {
	data := make([]byte, 132) // P521 key size
	for i := range data {
		data[i] = byte(i + 1) // non-zero data
	}
	key, err := selectSigningKeyConstructor(KEYCERT_SIGN_P521, data)
	assert.NoError(t, err, "P521 should succeed with valid data")
	assert.NotNil(t, key)
	assert.Equal(t, KEYCERT_SIGN_P521_SIZE, key.Len())
}

// TestSelectSigningKeyConstructor_RSAConstructs verifies RSA types now succeed with valid data.
func TestSelectSigningKeyConstructor_RSAConstructs(t *testing.T) {
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
			for i := range data {
				data[i] = byte(i%254 + 1) // non-zero data for valid RSA key
			}
			key, err := selectSigningKeyConstructor(tt.keyType, data)
			assert.NoError(t, err, "%s should succeed with valid data", tt.name)
			assert.NotNil(t, key)
			assert.Equal(t, tt.size, key.Len())
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
		rawBytes []byte
	}{
		{"NULL", certificate.CERT_NULL, []byte{certificate.CERT_NULL, 0x00, 0x00}},
		{"HIDDEN", certificate.CERT_HIDDEN, []byte{certificate.CERT_HIDDEN, 0x00, 0x00}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert, _, err := certificate.ReadCertificate(tt.rawBytes)
			require.NoError(t, err)

			keyCert, err := KeyCertificateFromCertificate(cert)
			assert.Error(t, err, "Should reject non-KEY certificate type %d", tt.certType)
			assert.Nil(t, keyCert)
			assert.Contains(t, err.Error(), "invalid certificate type")
		})
	}
}

// TestConstructPublicKey_P256_ConstructsKey verifies ECDH-P256 key is constructed
// successfully and NewEncrypter returns "not yet implemented" (ECIES-P256 pending).
func TestConstructPublicKey_P256_ConstructsKey(t *testing.T) {
	keyCert, err := NewKeyCertificateWithTypes(KEYCERT_SIGN_ED25519, KEYCERT_CRYPTO_P256)
	require.NoError(t, err)

	data := make([]byte, KEYCERT_PUBKEY_SIZE)
	pk, err := keyCert.ConstructPublicKey(data)
	assert.NoError(t, err)
	require.NotNil(t, pk)
	assert.Equal(t, KEYCERT_CRYPTO_P256_SIZE, pk.Len())
	_, encErr := pk.NewEncrypter()
	assert.Error(t, encErr, "NewEncrypter should return error: ECIES not yet implemented")
	assert.Contains(t, encErr.Error(), "not yet implemented")
}

// TestConstructPublicKey_P384_ConstructsKey verifies ECDH-P384 key is constructed
// successfully and NewEncrypter returns "not yet implemented".
func TestConstructPublicKey_P384_ConstructsKey(t *testing.T) {
	keyCert, err := NewKeyCertificateWithTypes(KEYCERT_SIGN_ED25519, KEYCERT_CRYPTO_P384)
	require.NoError(t, err)

	data := make([]byte, KEYCERT_PUBKEY_SIZE)
	pk, err := keyCert.ConstructPublicKey(data)
	assert.NoError(t, err)
	require.NotNil(t, pk)
	assert.Equal(t, KEYCERT_CRYPTO_P384_SIZE, pk.Len())
	_, encErr := pk.NewEncrypter()
	assert.Error(t, encErr, "NewEncrypter should return error: ECIES not yet implemented")
	assert.Contains(t, encErr.Error(), "not yet implemented")
}

// TestConstructPublicKey_P521_ConstructsKey verifies ECDH-P521 key is constructed
// successfully and NewEncrypter returns "not yet implemented".
func TestConstructPublicKey_P521_ConstructsKey(t *testing.T) {
	keyCert, err := NewKeyCertificateWithTypes(KEYCERT_SIGN_ED25519, KEYCERT_CRYPTO_P521)
	require.NoError(t, err)

	data := make([]byte, KEYCERT_PUBKEY_SIZE)
	pk, err := keyCert.ConstructPublicKey(data)
	assert.NoError(t, err)
	require.NotNil(t, pk)
	assert.Equal(t, KEYCERT_CRYPTO_P521_SIZE, pk.Len())
	_, encErr := pk.NewEncrypter()
	assert.Error(t, encErr, "NewEncrypter should return error: ECIES not yet implemented")
	assert.Contains(t, encErr.Error(), "not yet implemented")
}

// TestConstructPublicKey_ReservedNone_ReturnsReservedError verifies that
// KEYCERT_CRYPTO_RESERVED_NONE (255) returns a specific "reserved" error.
func TestConstructPublicKey_ReservedNone_ReturnsReservedError(t *testing.T) {
	payload := []byte{0x00, 0x07, 0x00, 0xFF} // signing=Ed25519, crypto=255
	cert, err := certificate.NewCertificateWithType(certificate.CERT_KEY, payload)
	require.NoError(t, err)

	keyCert, err := KeyCertificateFromCertificate(cert)
	require.NoError(t, err)

	data := make([]byte, KEYCERT_PUBKEY_SIZE)
	pk, err := keyCert.ConstructPublicKey(data)
	assert.Error(t, err)
	assert.Nil(t, pk)
	assert.Contains(t, err.Error(), "reserved")
	assert.Contains(t, err.Error(), "RESERVED_NONE")
}

// TestConstructPublicKey_AllUnimplementedTypes covers P256/384/521 crypto types:
// construction now succeeds (using ecdsa.NewECP* for byte validation),
// while NewEncrypter correctly signals that ECIES encryption is not yet implemented.
func TestConstructPublicKey_AllUnimplementedTypes(t *testing.T) {
	tests := []struct {
		name       string
		cryptoType int
		keySize    int
	}{
		{"P256", KEYCERT_CRYPTO_P256, KEYCERT_CRYPTO_P256_SIZE},
		{"P384", KEYCERT_CRYPTO_P384, KEYCERT_CRYPTO_P384_SIZE},
		{"P521", KEYCERT_CRYPTO_P521, KEYCERT_CRYPTO_P521_SIZE},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyCert, err := NewKeyCertificateWithTypes(KEYCERT_SIGN_ED25519, tt.cryptoType)
			require.NoError(t, err)

			data := make([]byte, KEYCERT_PUBKEY_SIZE)
			pk, err := keyCert.ConstructPublicKey(data)
			assert.NoError(t, err)
			require.NotNil(t, pk)
			assert.Equal(t, tt.keySize, pk.Len())
			_, encErr := pk.NewEncrypter()
			assert.Error(t, encErr, "NewEncrypter should return error")
			assert.Contains(t, encErr.Error(), "not yet implemented")
		})
	}
}

// TestConstructPublicKey_TrulyUnknownType verifies that types not in
// any known range still get an "unknown" error (not "unimplemented").
func TestConstructPublicKey_TrulyUnknownType(t *testing.T) {
	payload := []byte{0x00, 0x07, 0x00, 0xC8} // signing=Ed25519, crypto=200
	cert, err := certificate.NewCertificateWithType(certificate.CERT_KEY, payload)
	require.NoError(t, err)

	keyCert, err := KeyCertificateFromCertificate(cert)
	require.NoError(t, err)

	data := make([]byte, KEYCERT_PUBKEY_SIZE)
	pk, err := keyCert.ConstructPublicKey(data)
	assert.Error(t, err)
	assert.Nil(t, pk)
	assert.Contains(t, err.Error(), "unknown")
}

// TestNewKeyCertificate_PayloadTooShort_ReturnsError verifies strict payload
// length enforcement (spec: "prohibit excess data").
func TestNewKeyCertificate_PayloadTooShort_ReturnsError(t *testing.T) {
	rawBytes := []byte{0x05, 0x00, 0x04, 0x00, 0x03, 0x00, 0x04} // sig=P521, crypto=X25519
	keyCert, _, err := NewKeyCertificate(rawBytes)
	assert.Error(t, err, "Should reject P521 cert with insufficient payload")
	assert.Nil(t, keyCert)
	assert.Contains(t, err.Error(), "payload too short")
}

// TestNewKeyCertificate_PayloadExactSize_Succeeds verifies that payload with
// exactly the right size for the declared key types is accepted.
func TestNewKeyCertificate_PayloadExactSize_Succeeds(t *testing.T) {
	keyCert, _, err := NewKeyCertificate(testKeyCertBytesEd25519X25519)
	assert.NoError(t, err)
	assert.NotNil(t, keyCert)
}

// TestNewKeyCertificate_ShortPayload_ReturnsError verifies that
// NewKeyCertificate rejects raw bytes with insufficient payload for a KEY cert.
func TestNewKeyCertificate_ShortPayload_ReturnsError(t *testing.T) {
	rawBytes := []byte{0x05, 0x00, 0x02, 0x00, 0x07}
	keyCert, _, err := NewKeyCertificate(rawBytes)
	assert.Error(t, err)
	assert.Nil(t, keyCert)
	assert.Contains(t, err.Error(), "too short")
}

// TestValidateSigningKeyData_CorrectErrorMessage verifies the error message
// is returned correctly (functionally testing the fix).
func TestValidateSigningKeyData_CorrectErrorMessage(t *testing.T) {
	err := validateSigningKeyData(10, 32)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not enough data")
}

// TestValidateSigningKeyData_ExactSize_NoError verifies exact size passes.
func TestValidateSigningKeyData_ExactSize_NoError(t *testing.T) {
	err := validateSigningKeyData(32, 32)
	assert.NoError(t, err)
}

// TestConstructSigningPublicKey_RSA_InsufficientData verifies RSA types
// give clear errors with insufficient data.
func TestConstructSigningPublicKey_RSA_InsufficientData(t *testing.T) {
	rsaTypes := []struct {
		name    string
		keyType int
		size    int
	}{
		{"RSA2048", KEYCERT_SIGN_RSA2048, KEYCERT_SIGN_RSA2048_SIZE},
		{"RSA3072", KEYCERT_SIGN_RSA3072, KEYCERT_SIGN_RSA3072_SIZE},
		{"RSA4096", KEYCERT_SIGN_RSA4096, KEYCERT_SIGN_RSA4096_SIZE},
	}

	for _, tt := range rsaTypes {
		t.Run(tt.name, func(t *testing.T) {
			data := make([]byte, tt.size-1) // one byte short
			key, err := selectSigningKeyConstructor(tt.keyType, data)
			assert.Error(t, err, "%s should fail with insufficient data", tt.name)
			assert.Nil(t, key)
			assert.Contains(t, err.Error(), "insufficient data")
		})
	}
}

// TestConstructEd25519Key_TooShort verifies error on insufficient data.
func TestConstructEd25519Key_TooShort(t *testing.T) {
	data := make([]byte, 31)
	_, err := constructEd25519Key(data)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "insufficient data")
}

// TestKeyCertificateFromCertificate_WithExcessPayload verifies that
// KeyCertificateFromCertificate correctly parses a certificate with extra
// payload bytes (e.g., P521 with 4 excess signing key data bytes).
func TestKeyCertificateFromCertificate_WithExcessPayload(t *testing.T) {
	payload := []byte{0x00, 0x03, 0x00, 0x00, 0xDE, 0xAD, 0xBE, 0xEF}
	cert, err := certificate.NewCertificateWithType(certificate.CERT_KEY, payload)
	require.NoError(t, err)

	keyCert, err := KeyCertificateFromCertificate(cert)
	require.NoError(t, err)
	require.NotNil(t, keyCert)

	assert.Equal(t, KEYCERT_SIGN_P521, keyCert.SigningPublicKeyType())
	assert.Equal(t, KEYCERT_CRYPTO_ELG, keyCert.PublicKeyType())

	data, err := keyCert.Data()
	require.NoError(t, err)
	assert.Equal(t, 8, len(data))
}

// TestExcessPayloadRejected verifies that a Key Certificate whose payload is
// longer than the exact expected size is rejected.
// Per I2P spec: "implementers are cautioned to prohibit excess data in Certificates".
// Trigger: Ed25519/X25519 expects exactly 4-byte payload; a 5-byte payload must fail.
func TestExcessPayloadRejected(t *testing.T) {
	// Craft a valid Ed25519/X25519 key cert with one extra garbage byte in the payload.
	// Format: [type=0x05, len_hi, len_lo, spk_type_hi, spk_type_lo, cpk_type_hi, cpk_type_lo, garbage]
	// len = 5 (4 type bytes + 1 garbage byte)
	rawBytes := []byte{0x05, 0x00, 0x05, 0x00, 0x07, 0x00, 0x04, 0xFF}
	keyCert, _, err := NewKeyCertificate(rawBytes)
	assert.Error(t, err, "Certificate with excess payload must be rejected per I2P spec")
	assert.Nil(t, keyCert)
	assert.Contains(t, err.Error(), "too long",
		"Error message should indicate payload is too long, not just too short")
}

// TestExcessPayloadRejected_DSAElGamal verifies that a DSA/ElGamal Key Certificate
// whose payload contains excess bytes is also rejected.
func TestExcessPayloadRejected_DSAElGamal(t *testing.T) {
	// DSA signing key (128 bytes) = KEYCERT_SPK_SIZE, no excess expected.
	// ElGamal crypto key (256 bytes) = KEYCERT_PUBKEY_SIZE, no excess expected.
	// Expected payload length: 4 bytes. A 5-byte payload must fail.
	rawBytes := []byte{0x05, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0xFF}
	keyCert, _, err := NewKeyCertificate(rawBytes)
	assert.Error(t, err, "DSA/ElGamal cert with excess payload must be rejected")
	assert.Nil(t, keyCert)
	assert.Contains(t, err.Error(), "too long")
}

// TestMLKEMHybridKeySize verifies GetMLKEMHybridKeySize returns spec-correct sizes
// and returns an error for non-MLKEM types.
func TestMLKEMHybridKeySize(t *testing.T) {
	tests := []struct {
		name       string
		cryptoType int
		wantSize   int
		wantErr    bool
	}{
		{"MLKEM512_X25519", KEYCERT_CRYPTO_MLKEM512_X25519, MLKEM512_X25519_HYBRID_SIZE, false},
		{"MLKEM768_X25519", KEYCERT_CRYPTO_MLKEM768_X25519, MLKEM768_X25519_HYBRID_SIZE, false},
		{"MLKEM1024_X25519", KEYCERT_CRYPTO_MLKEM1024_X25519, MLKEM1024_X25519_HYBRID_SIZE, false},
		{"X25519_not_hybrid", KEYCERT_CRYPTO_X25519, 0, true},
		{"ElGamal_not_hybrid", KEYCERT_CRYPTO_ELG, 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			size, err := GetMLKEMHybridKeySize(tt.cryptoType)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Equal(t, 0, size)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.wantSize, size)
			}
		})
	}
}

// TestMLKEMHybridSizes_Spec verifies the hybrid size constants match I2P Proposal 169.
// MLKEM-512 PK=800, MLKEM-768 PK=1184, MLKEM-1024 PK=1568; add 32 for X25519.
func TestMLKEMHybridSizes_Spec(t *testing.T) {
	assert.Equal(t, 832, MLKEM512_X25519_HYBRID_SIZE,
		"MLKEM512+X25519 hybrid must be 800+32=832 bytes (Proposal 169)")
	assert.Equal(t, 1216, MLKEM768_X25519_HYBRID_SIZE,
		"MLKEM768+X25519 hybrid must be 1184+32=1216 bytes (Proposal 169)")
	assert.Equal(t, 1600, MLKEM1024_X25519_HYBRID_SIZE,
		"MLKEM1024+X25519 hybrid must be 1568+32=1600 bytes (Proposal 169)")
}
