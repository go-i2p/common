package encrypted_leaseset

import (
	"crypto/rand"
	"testing"
	"time"

	"github.com/go-i2p/common/data"
	"github.com/go-i2p/common/destination"
	"github.com/go-i2p/common/key_certificate"
	"github.com/go-i2p/common/lease"
	"github.com/go-i2p/common/lease_set2"
	"github.com/go-i2p/crypto/curve25519"
	"github.com/go-i2p/crypto/ed25519"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.step.sm/crypto/x25519"
)

// TestEncryptDecryptRoundTrip tests full encryption and decryption cycle
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

// TestEncryptDecryptWithDifferentKeys tests that decryption fails with wrong key
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

// TestDecryptWithWrongCookieLength tests cookie length validation
func TestDecryptWithWrongCookieLength(t *testing.T) {
	els := &EncryptedLeaseSet{
		encryptedInnerData: make([]byte, 100),
	}

	_, err := els.DecryptInnerData(make([]byte, 16), nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid cookie length")
}

// TestEncryptWithCurve25519Key tests encryption with Curve25519 key type
func TestEncryptWithCurve25519Key(t *testing.T) {
	ls2 := createTestLeaseSet2ForEncryption(t)

	recipientPub, _, err := x25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	// Convert to Curve25519PublicKey type
	c25519Pub := curve25519.Curve25519PublicKey(recipientPub[:])

	var cookie [32]byte
	_, _ = rand.Read(cookie[:])

	encryptedData, err := EncryptInnerLeaseSet2(ls2, cookie, c25519Pub)
	require.NoError(t, err)
	assert.NotEmpty(t, encryptedData)
}

// TestEncryptWithByteSliceKey tests encryption with raw byte slice key
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

// TestEncryptWithInvalidKeyType tests error for invalid key type
func TestEncryptWithInvalidKeyType(t *testing.T) {
	ls2 := createTestLeaseSet2ForEncryption(t)

	var cookie [32]byte
	_, _ = rand.Read(cookie[:])

	_, err := EncryptInnerLeaseSet2(ls2, cookie, "not a key")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid public key type")
}

// TestEncryptWithWrongKeyLength tests error for wrong key length
func TestEncryptWithWrongKeyLength(t *testing.T) {
	ls2 := createTestLeaseSet2ForEncryption(t)

	var cookie [32]byte
	_, _ = rand.Read(cookie[:])

	_, err := EncryptInnerLeaseSet2(ls2, cookie, make([]byte, 16))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid public key length")
}

// Helper — same logic as constructor_test.go but avoiding import cycle
func createTestLeaseSet2ForEncryption(t *testing.T) *lease_set2.LeaseSet2 {
	t.Helper()

	keysData := make([]byte, 384)
	_, _ = rand.Read(keysData)
	certData := []byte{0x05, 0x00, 0x04, 0x00, 0x07, 0x00, 0x00}
	destBytes := append(keysData, certData...)

	dest, _, err := destination.ReadDestination(destBytes)
	require.NoError(t, err)

	x25519Pub, _, err := x25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	encryptionKey := lease_set2.EncryptionKey{
		KeyType: key_certificate.KEYCERT_CRYPTO_X25519,
		KeyLen:  32,
		KeyData: x25519Pub[:],
	}

	var tunnelGwHash data.Hash
	_, _ = rand.Read(tunnelGwHash[:])
	testLease2, err := lease.NewLease2(tunnelGwHash, 12345, time.Now().Add(10*time.Minute))
	require.NoError(t, err)

	_, ed25519SigningPriv, err := ed25519.GenerateEd25519KeyPair()
	require.NoError(t, err)

	ls2, err := lease_set2.NewLeaseSet2(
		dest,
		uint32(time.Now().Unix()),
		600,
		0,
		nil,
		data.Mapping{},
		[]lease_set2.EncryptionKey{encryptionKey},
		[]lease.Lease2{*testLease2},
		ed25519SigningPriv,
	)
	require.NoError(t, err)
	return &ls2
}
