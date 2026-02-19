package encrypted_leaseset

import (
	"crypto/rand"
	"testing"

	"github.com/go-i2p/crypto/curve25519"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.step.sm/crypto/x25519"
)

// ————————————————————————————————————————————————
// Unit tests for EncryptInnerLeaseSet2 and DecryptInnerData
// Source: encryption.go
// ————————————————————————————————————————————————

func TestEncryptDecryptRoundTrip(t *testing.T) {
	ls2 := createTestLeaseSet2ForEncryption(t)

	recipientPub, recipientPriv, err := x25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	var cookie [32]byte
	_, _ = rand.Read(cookie[:])

	encryptedData, err := EncryptInnerLeaseSet2(ls2, cookie, &recipientPub)
	require.NoError(t, err)
	assert.NotEmpty(t, encryptedData)
	assert.Greater(t, len(encryptedData), x25519.PublicKeySize+12+16)

	els := &EncryptedLeaseSet{
		encryptedInnerData: encryptedData,
	}

	decryptedLS2, err := els.DecryptInnerData(cookie[:], &recipientPriv)
	require.NoError(t, err)
	require.NotNil(t, decryptedLS2)

	assert.Equal(t, ls2.Published(), decryptedLS2.Published())
	assert.Equal(t, ls2.Expires(), decryptedLS2.Expires())
	assert.Equal(t, len(ls2.Leases()), len(decryptedLS2.Leases()))
}

func TestEncryptDecryptWithDifferentKeys(t *testing.T) {
	ls2 := createTestLeaseSet2ForEncryption(t)

	recipientPub1, _, err := x25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	_, recipientPriv2, err := x25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	var cookie [32]byte
	_, _ = rand.Read(cookie[:])

	encryptedData, err := EncryptInnerLeaseSet2(ls2, cookie, &recipientPub1)
	require.NoError(t, err)

	els := &EncryptedLeaseSet{
		encryptedInnerData: encryptedData,
	}

	decryptedLS2, err := els.DecryptInnerData(cookie[:], recipientPriv2)
	assert.Error(t, err)
	assert.Nil(t, decryptedLS2)
	assert.Contains(t, err.Error(), "decryption failed")
}

func TestDecryptWithWrongCookieLength(t *testing.T) {
	els := &EncryptedLeaseSet{
		encryptedInnerData: make([]byte, 100),
	}

	_, err := els.DecryptInnerData(make([]byte, 16), nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid cookie length")
}

func TestEncryptWithCurve25519Key(t *testing.T) {
	ls2 := createTestLeaseSet2ForEncryption(t)

	recipientPub, _, err := x25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	c25519Pub := curve25519.Curve25519PublicKey(recipientPub[:])

	var cookie [32]byte
	_, _ = rand.Read(cookie[:])

	encryptedData, err := EncryptInnerLeaseSet2(ls2, cookie, c25519Pub)
	require.NoError(t, err)
	assert.NotEmpty(t, encryptedData)
}

func TestEncryptWithByteSliceKey(t *testing.T) {
	ls2 := createTestLeaseSet2ForEncryption(t)

	recipientPub, _, err := x25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	var cookie [32]byte
	_, _ = rand.Read(cookie[:])

	encryptedData, err := EncryptInnerLeaseSet2(ls2, cookie, recipientPub[:])
	require.NoError(t, err)
	assert.NotEmpty(t, encryptedData)
}

func TestEncryptWithInvalidKeyType(t *testing.T) {
	ls2 := createTestLeaseSet2ForEncryption(t)

	var cookie [32]byte
	_, _ = rand.Read(cookie[:])

	_, err := EncryptInnerLeaseSet2(ls2, cookie, "not a key")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid public key type")
}

func TestEncryptWithWrongKeyLength(t *testing.T) {
	ls2 := createTestLeaseSet2ForEncryption(t)

	var cookie [32]byte
	_, _ = rand.Read(cookie[:])

	_, err := EncryptInnerLeaseSet2(ls2, cookie, make([]byte, 16))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid public key length")
}
