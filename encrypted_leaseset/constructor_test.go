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
	"github.com/go-i2p/crypto/ed25519"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.step.sm/crypto/x25519"
)

// ——— Test helpers ———

// createTestLeaseSet2 creates a minimal valid LeaseSet2 for testing.
func createTestLeaseSet2(t *testing.T) *lease_set2.LeaseSet2 {
	t.Helper()

	destBytes := createTestDestinationBytes(t)
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

// createTestDestinationBytes creates a 391-byte destination (ElGamal + Ed25519).
func createTestDestinationBytes(t *testing.T) []byte {
	t.Helper()

	keysData := make([]byte, 384)
	_, _ = rand.Read(keysData)

	certData := []byte{
		0x05,       // Certificate type = KEY
		0x00, 0x04, // Certificate length = 4
		0x00, 0x07, // Signing key type = Ed25519 (7)
		0x00, 0x00, // Crypto key type = ElGamal (0)
	}
	return append(keysData, certData...)
}

// ——— Constructor tests ———

func TestNewEncryptedLeaseSet(t *testing.T) {
	ls2 := createTestLeaseSet2(t)
	recipientPub, _, err := x25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	var cookie [32]byte
	_, _ = rand.Read(cookie[:])

	encryptedData, err := EncryptInnerLeaseSet2(ls2, cookie, &recipientPub)
	require.NoError(t, err)

	_, signingPriv, err := ed25519.GenerateEd25519KeyPair()
	require.NoError(t, err)

	blindedKey := make([]byte, 32)
	_, _ = rand.Read(blindedKey)
	published := uint32(time.Now().Unix())
	expires := uint16(600)

	els, err := NewEncryptedLeaseSet(
		key_certificate.KEYCERT_SIGN_ED25519,
		blindedKey,
		published,
		expires,
		0, // flags
		nil,
		encryptedData,
		signingPriv,
	)
	require.NoError(t, err)

	assert.Equal(t, uint16(key_certificate.KEYCERT_SIGN_ED25519), els.SigType())
	assert.Equal(t, blindedKey, els.BlindedPublicKey())
	assert.Equal(t, published, els.Published())
	assert.Equal(t, expires, els.Expires())
	assert.Equal(t, uint16(0), els.Flags())
	assert.Equal(t, uint16(len(encryptedData)), els.InnerLength())
	assert.Equal(t, encryptedData, els.EncryptedInnerData())
	assert.NotNil(t, els.Signature())
}

func TestNewEncryptedLeaseSetFromDestination(t *testing.T) {
	ls2 := createTestLeaseSet2(t)
	recipientPub, _, err := x25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	var cookie [32]byte
	_, _ = rand.Read(cookie[:])

	encryptedData, err := EncryptInnerLeaseSet2(ls2, cookie, &recipientPub)
	require.NoError(t, err)

	_, signingPriv, err := ed25519.GenerateEd25519KeyPair()
	require.NoError(t, err)

	// Create a blinded destination
	destBytes := createTestDestinationBytes(t)
	dest, _, err := destination.ReadDestination(destBytes)
	require.NoError(t, err)

	els, err := NewEncryptedLeaseSetFromDestination(
		dest,
		uint32(time.Now().Unix()),
		600,
		0,
		nil,
		encryptedData,
		signingPriv,
	)
	require.NoError(t, err)
	assert.Equal(t, uint16(key_certificate.KEYCERT_SIGN_ED25519), els.SigType())
	assert.Len(t, els.BlindedPublicKey(), 32)
}

func TestNewEncryptedLeaseSetWithByteSliceKey(t *testing.T) {
	ls2 := createTestLeaseSet2(t)
	recipientPub, _, err := x25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	var cookie [32]byte
	_, _ = rand.Read(cookie[:])
	encryptedData, err := EncryptInnerLeaseSet2(ls2, cookie, &recipientPub)
	require.NoError(t, err)

	_, signingPriv, err := ed25519.GenerateEd25519KeyPair()
	require.NoError(t, err)
	signingPrivBytes := signingPriv.Bytes()

	blindedKey := make([]byte, 32)
	_, _ = rand.Read(blindedKey)

	els, err := NewEncryptedLeaseSet(
		key_certificate.KEYCERT_SIGN_ED25519,
		blindedKey,
		uint32(time.Now().Unix()),
		600,
		0,
		nil,
		encryptedData,
		signingPrivBytes,
	)
	require.NoError(t, err)
	assert.NotNil(t, els.Signature())
}

func TestNewEncryptedLeaseSetReservedFlags(t *testing.T) {
	blindedKey := make([]byte, 32)
	_, _ = rand.Read(blindedKey)
	encData := make([]byte, ENCRYPTED_LEASESET_MIN_ENCRYPTED_SIZE)
	_, _ = rand.Read(encData)
	_, signingPriv, _ := ed25519.GenerateEd25519KeyPair()

	_, err := NewEncryptedLeaseSet(
		key_certificate.KEYCERT_SIGN_ED25519,
		blindedKey,
		uint32(time.Now().Unix()),
		600,
		0x0004, // reserved bit 2
		nil,
		encData,
		signingPriv,
	)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "reserved flag bits")
}

func TestNewEncryptedLeaseSetZeroExpires(t *testing.T) {
	blindedKey := make([]byte, 32)
	_, _ = rand.Read(blindedKey)
	encData := make([]byte, ENCRYPTED_LEASESET_MIN_ENCRYPTED_SIZE)
	_, _ = rand.Read(encData)
	_, signingPriv, _ := ed25519.GenerateEd25519KeyPair()

	_, err := NewEncryptedLeaseSet(
		key_certificate.KEYCERT_SIGN_ED25519,
		blindedKey,
		uint32(time.Now().Unix()),
		0, // invalid
		0,
		nil,
		encData,
		signingPriv,
	)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "expires offset cannot be zero")
}

func TestNewEncryptedLeaseSetEmptyEncryptedData(t *testing.T) {
	blindedKey := make([]byte, 32)
	_, signingPriv, _ := ed25519.GenerateEd25519KeyPair()

	_, err := NewEncryptedLeaseSet(
		key_certificate.KEYCERT_SIGN_ED25519,
		blindedKey,
		uint32(time.Now().Unix()),
		600,
		0,
		nil,
		[]byte{},
		signingPriv,
	)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "encrypted inner data cannot be empty")
}

func TestNewEncryptedLeaseSetTooShortEncryptedData(t *testing.T) {
	blindedKey := make([]byte, 32)
	_, signingPriv, _ := ed25519.GenerateEd25519KeyPair()

	_, err := NewEncryptedLeaseSet(
		key_certificate.KEYCERT_SIGN_ED25519,
		blindedKey,
		uint32(time.Now().Unix()),
		600,
		0,
		nil,
		make([]byte, 50), // < 61 minimum
		signingPriv,
	)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "encrypted inner data size")
}

func TestNewEncryptedLeaseSetInvalidKeyType(t *testing.T) {
	blindedKey := make([]byte, 32)
	encData := make([]byte, ENCRYPTED_LEASESET_MIN_ENCRYPTED_SIZE)

	_, err := NewEncryptedLeaseSet(
		key_certificate.KEYCERT_SIGN_ED25519,
		blindedKey,
		uint32(time.Now().Unix()),
		600,
		0,
		nil,
		encData,
		"not a key",
	)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported signing key type")
}

func TestNewEncryptedLeaseSetInvalidKeyLength(t *testing.T) {
	blindedKey := make([]byte, 32)
	encData := make([]byte, ENCRYPTED_LEASESET_MIN_ENCRYPTED_SIZE)

	_, err := NewEncryptedLeaseSet(
		key_certificate.KEYCERT_SIGN_ED25519,
		blindedKey,
		uint32(time.Now().Unix()),
		600,
		0,
		nil,
		encData,
		make([]byte, 32), // wrong size for Ed25519 private key (should be 64)
	)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "byte slice signing key must be")
}

func TestNewEncryptedLeaseSetOfflineSignatureFlag(t *testing.T) {
	blindedKey := make([]byte, 32)
	encData := make([]byte, ENCRYPTED_LEASESET_MIN_ENCRYPTED_SIZE)
	_, signingPriv, _ := ed25519.GenerateEd25519KeyPair()

	// Flag set but no offline sig
	_, err := NewEncryptedLeaseSet(
		key_certificate.KEYCERT_SIGN_ED25519,
		blindedKey,
		uint32(time.Now().Unix()),
		600,
		ENCRYPTED_LEASESET_FLAG_OFFLINE_KEYS,
		nil,
		encData,
		signingPriv,
	)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "OFFLINE_KEYS flag set but no offline signature provided")
}

func TestNewEncryptedLeaseSetRoundTrip(t *testing.T) {
	ls2 := createTestLeaseSet2(t)
	recipientPub, recipientPriv, err := x25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	var cookie [32]byte
	_, _ = rand.Read(cookie[:])
	encryptedData, err := EncryptInnerLeaseSet2(ls2, cookie, &recipientPub)
	require.NoError(t, err)

	_, signingPriv, err := ed25519.GenerateEd25519KeyPair()
	require.NoError(t, err)

	blindedKey := make([]byte, 32)
	_, _ = rand.Read(blindedKey)

	original, err := NewEncryptedLeaseSet(
		key_certificate.KEYCERT_SIGN_ED25519,
		blindedKey,
		uint32(time.Now().Unix()),
		600,
		0,
		nil,
		encryptedData,
		signingPriv,
	)
	require.NoError(t, err)

	serialized, err := original.Bytes()
	require.NoError(t, err)

	parsed, remainder, err := ReadEncryptedLeaseSet(serialized)
	require.NoError(t, err)
	assert.Empty(t, remainder)

	assert.Equal(t, original.SigType(), parsed.SigType())
	assert.Equal(t, original.BlindedPublicKey(), parsed.BlindedPublicKey())
	assert.Equal(t, original.Published(), parsed.Published())
	assert.Equal(t, original.Expires(), parsed.Expires())
	assert.Equal(t, original.Flags(), parsed.Flags())
	assert.Equal(t, original.InnerLength(), parsed.InnerLength())
	assert.Equal(t, original.EncryptedInnerData(), parsed.EncryptedInnerData())

	// Verify decryption still works
	decrypted, err := parsed.DecryptInnerData(cookie[:], &recipientPriv)
	require.NoError(t, err)
	assert.NotNil(t, decrypted)
	assert.Equal(t, ls2.Published(), decrypted.Published())
}

func TestEncryptedLeaseSetValidateViaConstructor(t *testing.T) {
	ls2 := createTestLeaseSet2(t)
	recipientPub, _, err := x25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	var cookie [32]byte
	_, _ = rand.Read(cookie[:])
	encryptedData, err := EncryptInnerLeaseSet2(ls2, cookie, &recipientPub)
	require.NoError(t, err)

	_, signingPriv, err := ed25519.GenerateEd25519KeyPair()
	require.NoError(t, err)

	blindedKey := make([]byte, 32)
	_, _ = rand.Read(blindedKey)

	els, err := NewEncryptedLeaseSet(
		key_certificate.KEYCERT_SIGN_ED25519,
		blindedKey,
		uint32(time.Now().Unix()),
		600,
		0,
		nil,
		encryptedData,
		signingPriv,
	)
	require.NoError(t, err)

	assert.NoError(t, els.Validate())
	assert.True(t, els.IsValid())
}
