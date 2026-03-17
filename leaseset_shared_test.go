package common

import (
	"crypto/ed25519"
	"encoding/binary"
	"testing"

	"github.com/go-i2p/common/data"
	"github.com/go-i2p/common/key_certificate"
	sig "github.com/go-i2p/common/signature"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- helpers ---------------------------------------------------------------

// buildTestDestinationBytes builds a minimal 391-byte destination payload:
//
//	256 (public key) + 128 (signing key) = 384 bytes keys
//	+ 7 bytes KEY certificate (type=5, len=4, sigType, cryptoType)
func buildTestDestinationBytes(sigType uint16) []byte {
	keysData := make([]byte, 384)
	for i := range keysData {
		keysData[i] = byte(i % 256)
	}

	certData := []byte{
		0x05,       // Certificate type = KEY (5)
		0x00, 0x04, // Certificate length = 4 bytes
		0x00, 0x00, // Signing key type
		0x00, 0x00, // Crypto key type = ElGamal
	}
	binary.BigEndian.PutUint16(certData[3:5], sigType)
	return append(keysData, certData...)
}

// buildHeaderAfterDest constructs published(4)+expires(2)+flags(2)+emptyOptions(2).
func buildHeaderAfterDest(published uint32, expires, flags uint16) []byte {
	buf := make([]byte, 0, 10)
	buf = AppendBigEndianUint32(buf, published)
	buf = AppendBigEndianUint16(buf, expires)
	buf = AppendBigEndianUint16(buf, flags)
	buf = append(buf, 0x00, 0x00) // empty mapping
	return buf
}

// testApplier is a minimal LeaseSetFieldApplier for testing ParseAndApplyCommonPrefix.
type testApplier struct {
	fields LeaseSetCommonFields
}

func (a *testApplier) ApplyCommonFields(f LeaseSetCommonFields) {
	a.fields = f
}

// --- ValidateMinDataSize ---------------------------------------------------

func TestValidateMinDataSize(t *testing.T) {
	tests := []struct {
		name    string
		dataLen int
		minSize int
		wantErr bool
	}{
		{"exact match", 100, 100, false},
		{"larger", 200, 100, false},
		{"too short", 5, 100, true},
		{"zero length", 0, 1, true},
		{"zero min", 0, 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateMinDataSize(tt.dataLen, tt.minSize, "TestStruct")
			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "too short")
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// --- ValidateLeaseSetHeaderSize --------------------------------------------

func TestValidateLeaseSetHeaderSize(t *testing.T) {
	tests := []struct {
		name    string
		dataLen int
		wantErr bool
	}{
		{"sufficient", LeaseSetHeaderFieldsSize, false},
		{"more than needed", LeaseSetHeaderFieldsSize + 10, false},
		{"too short", LeaseSetHeaderFieldsSize - 1, true},
		{"zero", 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateLeaseSetHeaderSize(tt.dataLen, "TestStruct")
			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "header")
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// --- ParseLeaseSetHeaderFields ---------------------------------------------

func TestParseLeaseSetHeaderFields(t *testing.T) {
	buf := make([]byte, 12) // 8 header + 4 trailing
	binary.BigEndian.PutUint32(buf[0:4], 1735689600)
	binary.BigEndian.PutUint16(buf[4:6], 600)
	binary.BigEndian.PutUint16(buf[6:8], 0x0001)
	buf[8] = 0xAA
	buf[9] = 0xBB
	buf[10] = 0xCC
	buf[11] = 0xDD

	published, expires, flags, remainder := ParseLeaseSetHeaderFields(buf)
	assert.Equal(t, uint32(1735689600), published)
	assert.Equal(t, uint16(600), expires)
	assert.Equal(t, uint16(1), flags)
	assert.Equal(t, []byte{0xAA, 0xBB, 0xCC, 0xDD}, remainder)
}

// --- AppendBigEndianUint16 / AppendBigEndianUint32 -------------------------

func TestAppendBigEndianUint16(t *testing.T) {
	buf := AppendBigEndianUint16(nil, 0x1234)
	require.Len(t, buf, 2)
	assert.Equal(t, uint16(0x1234), binary.BigEndian.Uint16(buf))
}

func TestAppendBigEndianUint32(t *testing.T) {
	buf := AppendBigEndianUint32(nil, 0xDEADBEEF)
	require.Len(t, buf, 4)
	assert.Equal(t, uint32(0xDEADBEEF), binary.BigEndian.Uint32(buf))
}

func TestAppendBigEndianUint16_Chained(t *testing.T) {
	buf := AppendBigEndianUint16([]byte{0xFF}, 0x0001)
	require.Len(t, buf, 3)
	assert.Equal(t, byte(0xFF), buf[0])
	assert.Equal(t, uint16(1), binary.BigEndian.Uint16(buf[1:3]))
}

func TestAppendBigEndianUint32_Chained(t *testing.T) {
	buf := AppendBigEndianUint32([]byte{0x01, 0x02}, 42)
	require.Len(t, buf, 6)
	assert.Equal(t, uint32(42), binary.BigEndian.Uint32(buf[2:6]))
}

// --- PrependLeaseSetTypeByte -----------------------------------------------

func TestPrependLeaseSetTypeByte(t *testing.T) {
	content := []byte{0x01, 0x02, 0x03}
	result := PrependLeaseSetTypeByte(0x05, content)
	require.Len(t, result, 4)
	assert.Equal(t, byte(0x05), result[0])
	assert.Equal(t, content, result[1:])
}

func TestPrependLeaseSetTypeByte_EmptyContent(t *testing.T) {
	result := PrependLeaseSetTypeByte(0xFF, nil)
	require.Len(t, result, 1)
	assert.Equal(t, byte(0xFF), result[0])
}

// --- ExtractEd25519PrivateKey ----------------------------------------------

func TestExtractEd25519PrivateKey_FromPrivateKey(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	extracted, err := ExtractEd25519PrivateKey(priv)
	assert.NoError(t, err)
	assert.Equal(t, priv, extracted)
}

func TestExtractEd25519PrivateKey_FromBytes(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	extracted, err := ExtractEd25519PrivateKey([]byte(priv))
	assert.NoError(t, err)
	assert.Equal(t, ed25519.PrivateKey(priv), extracted)
}

func TestExtractEd25519PrivateKey_WrongSizeBytes(t *testing.T) {
	_, err := ExtractEd25519PrivateKey([]byte{0x01, 0x02, 0x03})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid signing key length")
}

func TestExtractEd25519PrivateKey_Nil(t *testing.T) {
	_, err := ExtractEd25519PrivateKey(nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "nil")
}

func TestExtractEd25519PrivateKey_UnsupportedType(t *testing.T) {
	_, err := ExtractEd25519PrivateKey("not a key")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported signing key type")
}

// --- SignLeaseSetData ------------------------------------------------------

func TestSignLeaseSetData_Ed25519(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	data := []byte("test data to sign")
	sigType := uint16(sig.SIGNATURE_TYPE_EDDSA_SHA512_ED25519)

	sigBytes, err := SignLeaseSetData(priv, data, sigType)
	assert.NoError(t, err)
	require.Len(t, sigBytes, ed25519.SignatureSize)

	// Verify the signature is valid
	pub := priv.Public().(ed25519.PublicKey)
	assert.True(t, ed25519.Verify(pub, data, sigBytes))
}

func TestSignLeaseSetData_RedDSA(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	data := []byte("test data for reddsa")
	sigType := uint16(sig.SIGNATURE_TYPE_REDDSA_SHA512_ED25519)

	sigBytes, err := SignLeaseSetData(priv, data, sigType)
	assert.NoError(t, err)
	assert.Len(t, sigBytes, 64) // RedDSA produces 64-byte signatures
}

func TestSignLeaseSetData_Ed25519ph(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	data := []byte("test data for ed25519ph")
	sigType := uint16(sig.SIGNATURE_TYPE_EDDSA_SHA512_ED25519PH)

	sigBytes, err := SignLeaseSetData(priv, data, sigType)
	assert.NoError(t, err)
	assert.Len(t, sigBytes, 64)
}

func TestSignLeaseSetData_UnsupportedType(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	_, err = SignLeaseSetData(priv, []byte("data"), 9999)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not implemented")
}

func TestSignLeaseSetData_InvalidKey(t *testing.T) {
	_, err := SignLeaseSetData("bad key", []byte("data"),
		uint16(sig.SIGNATURE_TYPE_EDDSA_SHA512_ED25519))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported signing key type")
}

// --- DetermineSignatureType ------------------------------------------------

func TestDetermineSignatureType_NoOfflineSig(t *testing.T) {
	result := DetermineSignatureType(sig.SIGNATURE_TYPE_EDDSA_SHA512_ED25519, nil)
	assert.Equal(t, uint16(sig.SIGNATURE_TYPE_EDDSA_SHA512_ED25519), result)
}

// --- ParseDestinationFromData ----------------------------------------------

func TestParseDestinationFromData_Valid(t *testing.T) {
	destData := buildTestDestinationBytes(key_certificate.KEYCERT_SIGN_ED25519)
	trailing := []byte{0xDE, 0xAD}
	input := append(destData, trailing...)

	dest, rem, err := ParseDestinationFromData(input, "TestStruct")
	assert.NoError(t, err)
	assert.NotNil(t, dest)
	assert.Equal(t, trailing, rem)
}

func TestParseDestinationFromData_TruncatedData(t *testing.T) {
	_, _, err := ParseDestinationFromData([]byte{0x01, 0x02}, "TestStruct")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "destination")
}

// --- ParseEmbeddedMapping --------------------------------------------------

func TestParseEmbeddedMapping_EmptyMapping(t *testing.T) {
	// Empty mapping: 2-byte length = 0
	input := []byte{0x00, 0x00, 0xAA, 0xBB}
	mapping, rem, err := ParseEmbeddedMapping(input, "TestStruct")
	assert.NoError(t, err)
	_ = mapping
	// Remainder should be the trailing bytes
	assert.Equal(t, []byte{0xAA, 0xBB}, rem)
}

// --- ParseOfflineSignatureField --------------------------------------------

func TestParseOfflineSignatureField_NoOfflineKeys(t *testing.T) {
	input := []byte{0x01, 0x02, 0x03}
	offlineSig, rem, err := ParseOfflineSignatureField(false, 0, input, "TestStruct")
	assert.NoError(t, err)
	assert.Nil(t, offlineSig)
	assert.Equal(t, input, rem)
}

func TestParseOfflineSignatureField_WithOfflineKeys_TruncatedData(t *testing.T) {
	// Only a few bytes — too short for a valid offline signature
	input := []byte{0x01, 0x02}
	_, _, err := ParseOfflineSignatureField(true, uint16(sig.SIGNATURE_TYPE_EDDSA_SHA512_ED25519), input, "TestStruct")
	assert.Error(t, err)
}

// --- ParseLeaseSetSignature ------------------------------------------------

func TestParseLeaseSetSignature_Valid(t *testing.T) {
	// Build a 64-byte Ed25519 signature + trailing data
	sigData := make([]byte, sig.EdDSA_SHA512_Ed25519_SIZE)
	for i := range sigData {
		sigData[i] = byte(i)
	}
	trailing := []byte{0xDE, 0xAD}
	input := append(sigData, trailing...)

	signature, rem, err := ParseLeaseSetSignature(
		input,
		sig.SIGNATURE_TYPE_EDDSA_SHA512_ED25519,
		false, nil, "TestStruct",
	)
	assert.NoError(t, err)
	assert.True(t, signature.IsValid())
	assert.Equal(t, trailing, rem)
}

func TestParseLeaseSetSignature_TooShort(t *testing.T) {
	_, _, err := ParseLeaseSetSignature(
		[]byte{0x01},
		sig.SIGNATURE_TYPE_EDDSA_SHA512_ED25519,
		false, nil, "TestStruct",
	)
	assert.Error(t, err)
}

// --- ParseAndApplyCommonPrefix / ParseLeaseSetCommonPrefix -----------------

func TestParseAndApplyCommonPrefix_Valid(t *testing.T) {
	destBytes := buildTestDestinationBytes(key_certificate.KEYCERT_SIGN_ED25519)
	header := buildHeaderAfterDest(1735689600, 600, 0)
	input := append(destBytes, header...)

	applier := &testApplier{}
	rem, err := ParseAndApplyCommonPrefix(applier, input, 10, "TestStruct")
	assert.NoError(t, err)
	assert.Empty(t, rem)
	assert.Equal(t, uint32(1735689600), applier.fields.Published)
	assert.Equal(t, uint16(600), applier.fields.Expires)
	assert.Equal(t, uint16(0), applier.fields.Flags)
}

func TestParseAndApplyCommonPrefix_TooShort(t *testing.T) {
	applier := &testApplier{}
	_, err := ParseAndApplyCommonPrefix(applier, []byte{0x01}, 100, "TestStruct")
	assert.Error(t, err)
}

func TestParseLeaseSetCommonPrefix_TooShortForHeader(t *testing.T) {
	// Destination is valid but no header fields follow
	destBytes := buildTestDestinationBytes(key_certificate.KEYCERT_SIGN_ED25519)
	_, _, err := ParseLeaseSetCommonPrefix(destBytes, 10, "TestStruct")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "header")
}

// --- SerializeLeaseSetHeader -----------------------------------------------

func TestSerializeLeaseSetHeader_RoundTrip(t *testing.T) {
	// Build a real destination for serialization
	destBytes := buildTestDestinationBytes(key_certificate.KEYCERT_SIGN_ED25519)
	dest, _, err := ParseDestinationFromData(destBytes, "test")
	require.NoError(t, err)

	published := uint32(1735689600)
	expires := uint16(600)
	flags := uint16(0)

	headerBytes, err := SerializeLeaseSetHeader(dest, published, expires, flags, nil, data.Mapping{})
	assert.NoError(t, err)
	require.NotNil(t, headerBytes)

	// The header should start with the destination bytes
	assert.True(t, len(headerBytes) > len(destBytes))
}

// --- CreateLeaseSetSignature -----------------------------------------------

func TestCreateLeaseSetSignature_Ed25519(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	sigType := uint16(sig.SIGNATURE_TYPE_EDDSA_SHA512_ED25519)
	data := []byte("lease set content")

	signature, err := CreateLeaseSetSignature(priv, data, sigType, SignLeaseSetData)
	assert.NoError(t, err)
	assert.True(t, signature.IsValid())
}

func TestCreateLeaseSetSignature_UnsupportedType(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	// Signature type 0 (DSA_SHA1) has a known size but our signing dispatch
	// doesn't support it — SignLeaseSetData should error.
	_, err = CreateLeaseSetSignature(priv, []byte("data"), 9999, SignLeaseSetData)
	assert.Error(t, err)
}

// --- Constants -------------------------------------------------------------

func TestLeaseSetConstants(t *testing.T) {
	assert.Equal(t, 8, LeaseSetHeaderFieldsSize)
	assert.Equal(t, 1, LeaseSetFlagOfflineKeys)
}
