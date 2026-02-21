package encrypted_leaseset

import (
	"crypto/rand"
	"testing"
	"time"

	"github.com/go-i2p/common/key_certificate"
	goi2ped25519 "github.com/go-i2p/crypto/ed25519"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ————————————————————————————————————————————————
// Integration tests for constructor round-trips
// Source: constructor.go
// ————————————————————————————————————————————————

func TestNewEncryptedLeaseSetRoundTrip(t *testing.T) {
	ls2 := createTestLeaseSet2(t)

	var subcredential [32]byte
	_, _ = rand.Read(subcredential[:])
	published := uint32(time.Now().Unix())

	encryptedData, err := EncryptInnerLeaseSet2(ls2, subcredential, published)
	require.NoError(t, err)

	_, signingPriv, err := goi2ped25519.GenerateEd25519KeyPair()
	require.NoError(t, err)

	blindedKey := make([]byte, 32)
	_, _ = rand.Read(blindedKey)

	original, err := NewEncryptedLeaseSet(
		key_certificate.KEYCERT_SIGN_ED25519,
		blindedKey,
		published,
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

	// Verify decryption still works after round-trip through serialization
	decrypted, err := parsed.DecryptInnerData(subcredential)
	require.NoError(t, err)
	assert.NotNil(t, decrypted)
	assert.Equal(t, ls2.Published(), decrypted.Published())
}

func TestEncryptedLeaseSetValidateViaConstructor(t *testing.T) {
	ls2 := createTestLeaseSet2(t)

	var subcredential [32]byte
	_, _ = rand.Read(subcredential[:])
	published := uint32(time.Now().Unix())

	encryptedData, err := EncryptInnerLeaseSet2(ls2, subcredential, published)
	require.NoError(t, err)

	_, signingPriv, err := goi2ped25519.GenerateEd25519KeyPair()
	require.NoError(t, err)

	blindedKey := make([]byte, 32)
	_, _ = rand.Read(blindedKey)

	els, err := NewEncryptedLeaseSet(
		key_certificate.KEYCERT_SIGN_ED25519,
		blindedKey,
		published,
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
