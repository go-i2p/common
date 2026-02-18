package key_certificate

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-i2p/common/certificate"
)

// TestConstructPublicKey_X25519_StartAligned verifies that ConstructPublicKey
// extracts X25519 key from the start of the 256-byte field (bytes 0–31),
// not from the end (bytes 224–255).
// This was a critical bug: the spec says crypto public key is start-aligned.
func TestConstructPublicKey_X25519_StartAligned(t *testing.T) {
	keyCert, err := NewKeyCertificateWithTypes(KEYCERT_SIGN_ED25519, KEYCERT_CRYPTO_X25519)
	require.NoError(t, err)

	// Create 256-byte data with distinct pattern at the start and zeros elsewhere
	data := make([]byte, KEYCERT_PUBKEY_SIZE)
	for i := 0; i < KEYCERT_CRYPTO_X25519_SIZE; i++ {
		data[i] = byte(i + 1) // bytes 0–31 have non-zero pattern
	}
	// bytes 32–255 remain zero (this is where padding goes)

	pk, err := keyCert.ConstructPublicKey(data)
	require.NoError(t, err)
	require.NotNil(t, pk)

	assert.Equal(t, KEYCERT_CRYPTO_X25519_SIZE, pk.Len(),
		"X25519 public key should be 32 bytes")

	// Verify the key was extracted from the START, not the end
	pkBytes := pk.Bytes()
	assert.Equal(t, byte(1), pkBytes[0],
		"First byte should be 0x01 (from start-aligned position)")
	assert.Equal(t, byte(32), pkBytes[31],
		"Last byte should be 0x20 (byte 31 from start)")
}

// TestConstructPublicKey_X25519_NotEndAligned confirms the old bug is fixed:
// if key material is only at the end of the 256-byte field, the extracted key
// should be all zeros (since we now read from the start).
func TestConstructPublicKey_X25519_NotEndAligned(t *testing.T) {
	keyCert, err := NewKeyCertificateWithTypes(KEYCERT_SIGN_ED25519, KEYCERT_CRYPTO_X25519)
	require.NoError(t, err)

	// Place key material at the END (old incorrect position)
	data := make([]byte, KEYCERT_PUBKEY_SIZE)
	for i := KEYCERT_PUBKEY_SIZE - KEYCERT_CRYPTO_X25519_SIZE; i < KEYCERT_PUBKEY_SIZE; i++ {
		data[i] = byte(i - (KEYCERT_PUBKEY_SIZE - KEYCERT_CRYPTO_X25519_SIZE) + 1)
	}

	pk, err := keyCert.ConstructPublicKey(data)
	require.NoError(t, err)

	// The extracted key should be all zeros since bytes 0–31 are zero
	pkBytes := pk.Bytes()
	for i := 0; i < KEYCERT_CRYPTO_X25519_SIZE; i++ {
		assert.Equal(t, byte(0), pkBytes[i],
			"Key extracted from start should be zero when data is only at end")
	}
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
			// Verify start-aligned extraction
			assert.Equal(t, byte(0xA0), pk.Bytes()[0])
		})
	}
}

// TestRoundTripSerialization verifies that creating a KeyCertificate with
// NewKeyCertificateWithTypes, serializing with Data(), and re-parsing with
// NewKeyCertificate produces an equivalent certificate.
func TestRoundTripSerialization(t *testing.T) {
	tests := []struct {
		name        string
		signingType int
		cryptoType  int
	}{
		{"Ed25519_X25519", KEYCERT_SIGN_ED25519, KEYCERT_CRYPTO_X25519},
		{"DSA_ElGamal", KEYCERT_SIGN_DSA_SHA1, KEYCERT_CRYPTO_ELG},
		{"P256_ElGamal", KEYCERT_SIGN_P256, KEYCERT_CRYPTO_ELG},
		{"P384_ElGamal", KEYCERT_SIGN_P384, KEYCERT_CRYPTO_ELG},
		{"RedDSA_X25519", KEYCERT_SIGN_REDDSA_ED25519, KEYCERT_CRYPTO_X25519},
		{"Ed25519ph_X25519", KEYCERT_SIGN_ED25519PH, KEYCERT_CRYPTO_X25519},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create
			original, err := NewKeyCertificateWithTypes(tt.signingType, tt.cryptoType)
			require.NoError(t, err)

			// Serialize
			rawData := original.Certificate.RawBytes()
			require.NotEmpty(t, rawData, "RawBytes() should return non-empty data")

			// Re-parse: need to prepend the certificate header (type + length)
			certBytes := original.Certificate.Bytes()
			require.NotEmpty(t, certBytes, "Bytes() should return non-empty data")

			reparsed, _, err := NewKeyCertificate(certBytes)
			require.NoError(t, err)
			require.NotNil(t, reparsed)

			// Verify equivalence
			assert.Equal(t, tt.signingType, reparsed.SigningPublicKeyType(),
				"Round-trip should preserve signing type")
			assert.Equal(t, tt.cryptoType, reparsed.PublicKeyType(),
				"Round-trip should preserve crypto type")
			assert.Equal(t, original.SigningPublicKeySize(), reparsed.SigningPublicKeySize(),
				"Round-trip should preserve signing key size")
			assert.Equal(t, original.CryptoSize(), reparsed.CryptoSize(),
				"Round-trip should preserve crypto size")
			assert.Equal(t, original.SignatureSize(), reparsed.SignatureSize(),
				"Round-trip should preserve signature size")
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
			// Build raw certificate bytes: [type, length_hi, length_lo]
			// NULL cert: type=0, length=0
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

// TestNewKeyCertificate_ExcessTrailingData verifies that the remainder
// return value correctly captures bytes after the certificate.
func TestNewKeyCertificate_ExcessTrailingData(t *testing.T) {
	// Key certificate: type=5, length=4, payload=[0x00,0x07,0x00,0x04]
	// Then 3 trailing bytes
	certBytes := []byte{0x05, 0x00, 0x04, 0x00, 0x07, 0x00, 0x04, 0xAA, 0xBB, 0xCC}

	keyCert, remainder, err := NewKeyCertificate(certBytes)
	require.NoError(t, err)
	require.NotNil(t, keyCert)

	assert.Equal(t, KEYCERT_SIGN_ED25519, keyCert.SigningPublicKeyType())
	assert.Equal(t, KEYCERT_CRYPTO_X25519, keyCert.PublicKeyType())

	// Verify remainder contains the trailing bytes
	require.Len(t, remainder, 3, "Should have 3 remainder bytes")
	assert.Equal(t, byte(0xAA), remainder[0])
	assert.Equal(t, byte(0xBB), remainder[1])
	assert.Equal(t, byte(0xCC), remainder[2])
}

// TestConstructSigningPublicKey_DSA_NonZeroData tests DSA key construction
// with non-zero data patterns to verify correct byte extraction from the padded field.
func TestConstructSigningPublicKey_DSA_NonZeroData(t *testing.T) {
	keyCert, err := NewKeyCertificateWithTypes(KEYCERT_SIGN_DSA_SHA1, KEYCERT_CRYPTO_ELG)
	require.NoError(t, err)

	// Create 128-byte padded data with distinct pattern
	data := make([]byte, KEYCERT_SPK_SIZE)
	for i := range data {
		data[i] = byte(i + 1)
	}

	spk, err := keyCert.ConstructSigningPublicKey(data)
	require.NoError(t, err)
	require.NotNil(t, spk)
	assert.Equal(t, KEYCERT_SIGN_DSA_SHA1_SIZE, spk.Len())

	// Verify the data was correctly extracted
	spkBytes := spk.Bytes()
	assert.NotEqual(t, make([]byte, KEYCERT_SIGN_DSA_SHA1_SIZE), spkBytes,
		"DSA key bytes should not be all zeros when input has non-zero data")
}

// TestSigningPublicKeySize_UnknownTypeReturnsZero verifies that unknown signing
// types return 0 instead of the legacy 128-byte fallback.
func TestSigningPublicKeySize_UnknownTypeReturnsZero(t *testing.T) {
	keyCert := &KeyCertificate{}
	keyCert.SpkType = []byte{0x03, 0xe8} // type 1000 - unknown

	size := keyCert.SigningPublicKeySize()
	assert.Equal(t, 0, size,
		"SigningPublicKeySize should return 0 for unknown types, not 128")
}

// TestSigningPublicKeySize_ConsistentWithSigningKeySizes verifies the method
// returns the same values as the canonical SigningKeySizes map.
func TestSigningPublicKeySize_ConsistentWithSigningKeySizes(t *testing.T) {
	for sigType, info := range SigningKeySizes {
		keyCert, err := NewKeyCertificateWithTypes(sigType, KEYCERT_CRYPTO_X25519)
		require.NoError(t, err)

		size := keyCert.SigningPublicKeySize()
		assert.Equal(t, info.SigningPublicKeySize, size,
			"SigningPublicKeySize() should match SigningKeySizes map for type %d", sigType)
	}
}

// TestValidatePayloadLengthAgainstKeyTypes verifies the new payload validation.
func TestValidatePayloadLengthAgainstKeyTypes(t *testing.T) {
	tests := []struct {
		name    string
		sigType int
		cryType int
		dataLen int
		wantErr bool
	}{
		// Ed25519 (32 bytes) + X25519 (32 bytes): both fit in standard fields, no excess
		{"Ed25519_X25519_exact", KEYCERT_SIGN_ED25519, KEYCERT_CRYPTO_X25519, 4, false},
		// DSA (128 bytes) + ElGamal (256 bytes): both fit exactly, no excess
		{"DSA_ElGamal_exact", KEYCERT_SIGN_DSA_SHA1, KEYCERT_CRYPTO_ELG, 4, false},
		// P521 signing (132 bytes > 128 standard) needs 4 excess bytes
		{"P521_ElGamal_short", KEYCERT_SIGN_P521, KEYCERT_CRYPTO_ELG, 4, true},
		{"P521_ElGamal_enough", KEYCERT_SIGN_P521, KEYCERT_CRYPTO_ELG, 8, false},
		// RSA2048 (256 bytes > 128 standard) needs 128 excess bytes
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

// FuzzNewKeyCertificate exercises NewKeyCertificate with random binary input
// to verify it doesn't panic on malformed data.
func FuzzNewKeyCertificate(f *testing.F) {
	// Seed with valid key certificate data
	f.Add([]byte{0x05, 0x00, 0x04, 0x00, 0x07, 0x00, 0x04})
	f.Add([]byte{0x05, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00})
	// Seed with too-short data
	f.Add([]byte{0x05})
	f.Add([]byte{0x05, 0x00})
	// Seed with wrong certificate type
	f.Add([]byte{0x00, 0x00, 0x04, 0x00, 0x07, 0x00, 0x04})
	// Seed with excess data
	f.Add([]byte{0x05, 0x00, 0x04, 0x00, 0x07, 0x00, 0x04, 0xFF, 0xFF, 0xFF})

	f.Fuzz(func(t *testing.T, data []byte) {
		// Should never panic regardless of input
		keyCert, remainder, err := NewKeyCertificate(data)
		if err != nil {
			// Error is expected for malformed data
			return
		}
		// If no error, basic invariants should hold
		if keyCert == nil {
			t.Fatal("No error but keyCert is nil")
		}
		_ = keyCert.SigningPublicKeyType()
		_ = keyCert.PublicKeyType()
		_ = keyCert.SigningPublicKeySize()
		_ = keyCert.CryptoSize()
		_ = keyCert.SignatureSize()
		_ = remainder
	})
}
