package lease_set2

import (
	"crypto/ed25519"
	"testing"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/crypto/rand"

	"github.com/go-i2p/common/key_certificate"
	"github.com/go-i2p/common/lease"
	"github.com/go-i2p/common/offline_signature"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestVerifyRejectsExpiredOfflineSignature verifies that LeaseSet2 rejects an
// offline signature whose transient-key authorization window has closed, even
// though the destination's long-term key genuinely signed it. An expired
// transient key must not be usable forever.
func TestVerifyRejectsExpiredOfflineSignature(t *testing.T) {
	destPub, destPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	transientPub, transientPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	dest := createTestDestWithKey(t, destPub)

	// Correctly signed by the destination key, but expired an hour ago.
	offSig, err := offline_signature.CreateOfflineSignature(
		uint32(time.Now().Add(-time.Hour).Unix()),
		key_certificate.KEYCERT_SIGN_ED25519,
		transientPub,
		destPriv,
		key_certificate.KEYCERT_SIGN_ED25519,
	)
	require.NoError(t, err)

	l := createTestLease2(t, 0)
	encKey := EncryptionKey{
		KeyType: key_certificate.KEYCERT_CRYPTO_X25519,
		KeyLen:  32,
		KeyData: make([]byte, 32),
	}

	ls2, err := NewLeaseSet2(
		dest, uint32(time.Now().Unix()), 600, LEASESET2_FLAG_OFFLINE_KEYS, &offSig,
		common.Mapping{}, []EncryptionKey{encKey}, []lease.Lease2{*l}, transientPriv,
	)
	require.NoError(t, err)

	err = ls2.Verify()
	assert.Error(t, err, "Verify must reject an expired offline signature")
	assert.Contains(t, err.Error(), "expired")
}
