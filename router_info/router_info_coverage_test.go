package router_info

import (
	"testing"
	"time"

	"github.com/go-i2p/crypto/ed25519"
	"github.com/go-i2p/crypto/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-i2p/common/data"
	"github.com/go-i2p/common/signature"
)

// =============================================================================
// createSignerFromPrivateKey coverage
// =============================================================================

func TestCreateSignerFromPrivateKey_NilKey(t *testing.T) {
	_, err := createSignerFromPrivateKey(nil, signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "nil")
}

func TestCreateSignerFromPrivateKey_DSA_SHA1(t *testing.T) {
	privKey, _ := generateEd25519KeyPair(t)
	_, err := createSignerFromPrivateKey(&privKey, signature.SIGNATURE_TYPE_DSA_SHA1)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "legacy unsupported")
	assert.Contains(t, err.Error(), "DSA_SHA1")
}

func TestCreateSignerFromPrivateKey_RSA_Types(t *testing.T) {
	privKey, _ := generateEd25519KeyPair(t)
	rsaTypes := []int{
		signature.SIGNATURE_TYPE_RSA_SHA256_2048,
		signature.SIGNATURE_TYPE_RSA_SHA384_3072,
		signature.SIGNATURE_TYPE_RSA_SHA512_4096,
	}
	for _, sigType := range rsaTypes {
		_, err := createSignerFromPrivateKey(&privKey, sigType)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "legacy unsupported")
		assert.Contains(t, err.Error(), "RSA")
	}
}

func TestCreateSignerFromPrivateKey_UnknownType(t *testing.T) {
	privKey, _ := generateEd25519KeyPair(t)
	_, err := createSignerFromPrivateKey(&privKey, 999)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported signature type")
}

func TestCreateSignerFromPrivateKey_Ed25519_Success(t *testing.T) {
	privKey, _ := generateEd25519KeyPair(t)
	signer, err := createSignerFromPrivateKey(&privKey, signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519)
	assert.NoError(t, err)
	assert.NotNil(t, signer)
}

// =============================================================================
// createEd25519Signer coverage
// =============================================================================

// badSigningKey is a types.SigningPrivateKey that is NOT *ed25519.Ed25519PrivateKey.
type badSigningKey []byte

func (b badSigningKey) Len() int                                   { return len(b) }
func (b badSigningKey) Bytes() []byte                              { return b }
func (b badSigningKey) NewSigner() (types.Signer, error)           { return nil, nil }
func (b badSigningKey) Public() (types.SigningPublicKey, error)    { return nil, nil }
func (b badSigningKey) Generate() (types.SigningPrivateKey, error) { return nil, nil }

func TestCreateEd25519Signer_WrongType(t *testing.T) {
	key := badSigningKey(make([]byte, 64))
	_, err := createEd25519Signer(key)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "expected *Ed25519PrivateKey")
}

func TestCreateEd25519Signer_WrongSize(t *testing.T) {
	shortKey := ed25519.Ed25519PrivateKey(make([]byte, 32))
	_, err := createEd25519Signer(&shortKey)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid Ed25519 private key size")
}

func TestCreateEd25519Signer_Success(t *testing.T) {
	privKey, _ := generateEd25519KeyPair(t)
	signer, err := createEd25519Signer(&privKey)
	assert.NoError(t, err)
	assert.NotNil(t, signer)
}

// =============================================================================
// validateTimestampAndSize coverage
// =============================================================================

func TestValidateTimestampAndSize_NilPublished(t *testing.T) {
	ri := &RouterInfo{published: nil}
	err := validateTimestampAndSize(ri)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "published date is required")
}

func TestValidateTimestampAndSize_ZeroPublished(t *testing.T) {
	zeroDate := data.Date{}
	ri := &RouterInfo{published: &zeroDate}
	err := validateTimestampAndSize(ri)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "published date cannot be zero")
}

func TestValidateTimestampAndSize_NilSize(t *testing.T) {
	d, err := data.DateFromTime(time.Now())
	require.NoError(t, err)
	ri := &RouterInfo{published: d, size: nil}
	err = validateTimestampAndSize(ri)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "size field is required")
}

func TestValidateTimestampAndSize_Valid(t *testing.T) {
	d, err := data.DateFromTime(time.Now())
	require.NoError(t, err)
	size, err := data.NewIntegerFromInt(1, 1)
	require.NoError(t, err)
	ri := &RouterInfo{published: d, size: size}
	err = validateTimestampAndSize(ri)
	assert.NoError(t, err)
}

// =============================================================================
// validatePatchVersionRange coverage
// =============================================================================

func TestValidatePatchVersionRange_BadMinor(t *testing.T) {
	_, err := validatePatchVersionRange("60", 8, "0.8.60")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid minor version")
}

func TestValidatePatchVersionRange_UnparseablePatch(t *testing.T) {
	_, err := validatePatchVersionRange("abc", 9, "0.9.abc")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Failed to parse version component 2")
}

func TestValidatePatchVersionRange_ValidInRange(t *testing.T) {
	ok, err := validatePatchVersionRange("60", 9, "0.9.60")
	assert.NoError(t, err)
	assert.True(t, ok)
}

func TestValidatePatchVersionRange_TooLow(t *testing.T) {
	ok, err := validatePatchVersionRange("10", 9, "0.9.10")
	assert.NoError(t, err)
	assert.False(t, ok)
}

// =============================================================================
// validateMinorVersion coverage
// =============================================================================

func TestValidateMinorVersion_NonZeroMajor(t *testing.T) {
	_, err := validateMinorVersion("9", 1, "1.9.60")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid major version")
}

func TestValidateMinorVersion_UnparseableMinor(t *testing.T) {
	_, err := validateMinorVersion("xyz", 0, "0.xyz.60")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Failed to parse version component 1")
}

func TestValidateMinorVersion_WrongMinor(t *testing.T) {
	_, err := validateMinorVersion("8", 0, "0.8.60")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid version at position 1")
}

func TestValidateMinorVersion_Valid(t *testing.T) {
	v, err := validateMinorVersion("9", 0, "0.9.60")
	assert.NoError(t, err)
	assert.Equal(t, 9, v)
}

// =============================================================================
// parseSignatureData coverage
// =============================================================================

func TestParseSignatureData_TooShort(t *testing.T) {
	shortData := make([]byte, 2)
	_, _, err := parseSignatureData(shortData, signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not enough data")
}

func TestParseSignatureData_Success(t *testing.T) {
	// Ed25519 signature is 64 bytes; provide 70 to have a remainder
	fullData := make([]byte, 70)
	sig, remainder, err := parseSignatureData(fullData, signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519)
	assert.NoError(t, err)
	assert.NotNil(t, sig)
	assert.Equal(t, 6, len(remainder))
}

// =============================================================================
// validateMajorVersion coverage
// =============================================================================

func TestValidateMajorVersion_Unparseable(t *testing.T) {
	_, err := validateMajorVersion("abc", "abc.9.60")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Failed to parse version component 0")
}

func TestValidateMajorVersion_NonZero(t *testing.T) {
	_, err := validateMajorVersion("1", "1.9.60")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid version at position 0")
}

func TestValidateMajorVersion_Valid(t *testing.T) {
	v, err := validateMajorVersion("0", "0.9.60")
	assert.NoError(t, err)
	assert.Equal(t, 0, v)
}

// =============================================================================
// parseAndValidateVersionString coverage
// =============================================================================

func TestParseAndValidateVersionString_BadFormat(t *testing.T) {
	_, err := parseAndValidateVersionString("0.9")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid version format")
}

func TestParseAndValidateVersionString_Valid(t *testing.T) {
	parts, err := parseAndValidateVersionString("0.9.64")
	assert.NoError(t, err)
	assert.Equal(t, 3, len(parts))
	assert.Equal(t, "0", parts[0])
	assert.Equal(t, "9", parts[1])
	assert.Equal(t, "64", parts[2])
}
