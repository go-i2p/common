package encrypted_leaseset

import (
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/go-i2p/crypto/rand"

	"github.com/go-i2p/common/data"
	"github.com/go-i2p/common/key_certificate"
	"github.com/go-i2p/common/lease_set2"
	"github.com/go-i2p/common/meta_leaseset"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestInnerMetaLeaseSetRoundTrip covers the spec-defined Layer 2 type-7
// ("Meta LS2") variant of the encrypted leaseset inner plaintext.
//
// Spec: https://geti2p.net/spec/encryptedleaseset §"Layer 2 (inner)":
//
//	Type : 1 byte — Either 3 (LS2) or 7 (Meta LS2)
//	Data : LeaseSet2 data for the given type. Includes the header and signature.
func TestInnerMetaLeaseSetRoundTrip(t *testing.T) {
	dest := createTestEd25519Destination(t)
	_, edPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	entryHash := make([]byte, 32)
	_, _ = rand.Read(entryHash)
	entry, err := meta_leaseset.NewMetaLeaseSetEntry(
		entryHash, meta_leaseset.META_LEASESET_ENTRY_TYPE_LEASESET2, 1,
		uint32(time.Now().Add(10*time.Minute).Unix()),
	)
	require.NoError(t, err)

	mls, err := meta_leaseset.NewMetaLeaseSet(
		dest, uint32(time.Now().Unix()), 600, 0, nil, data.Mapping{},
		[]meta_leaseset.MetaLeaseSetEntry{entry}, nil, edPriv,
	)
	require.NoError(t, err)

	var subcred [32]byte
	_, _ = rand.Read(subcred[:])
	published := uint32(time.Now().Unix())

	encrypted, err := EncryptInnerMetaLeaseSet(&mls, subcred, published)
	require.NoError(t, err)
	require.NotEmpty(t, encrypted)

	els := &EncryptedLeaseSet{
		sigType:            key_certificate.KEYCERT_SIGN_ED25519,
		published:          published,
		expires:            600,
		innerLength:        uint16(len(encrypted)),
		encryptedInnerData: encrypted,
	}

	inner, err := els.DecryptInnerLeaseSet(subcred)
	require.NoError(t, err)
	assert.Equal(t, byte(meta_leaseset.META_LEASESET_TYPE), inner.Type)
	assert.NotNil(t, inner.MetaLeaseSet, "type 7 must yield a MetaLeaseSet")
	assert.Nil(t, inner.LeaseSet2, "type 7 must not populate LeaseSet2")
	assert.Equal(t, 1, len(inner.MetaLeaseSet.Entries()))

	// The LeaseSet2-only accessor must reject a type-7 payload rather than
	// silently mis-parse it.
	_, err = els.DecryptInnerDataWithCredential(subcred, nil)
	assert.Error(t, err, "DecryptInnerData must reject a MetaLeaseSet inner payload")
}

// TestInnerLeaseSetTypeByteDispatch verifies the parser distinguishes the two
// spec-defined inner type bytes and rejects anything else.
func TestInnerLeaseSetTypeByteDispatch(t *testing.T) {
	// Type 3 path with a truncated body must fail as LeaseSet2, not fall through.
	_, err := parseDecryptedInnerLeaseSet([]byte{lease_set2.LEASESET2_DBSTORE_TYPE, 0x00})
	assert.Error(t, err, "truncated type-3 inner payload must be rejected")

	// Unknown type bytes are not permitted by the spec.
	_, err = parseDecryptedInnerLeaseSet([]byte{0x09, 0x00, 0x00})
	assert.Error(t, err, "unknown inner type byte must be rejected")

	// Empty plaintext.
	_, err = parseDecryptedInnerLeaseSet(nil)
	assert.Error(t, err, "empty inner plaintext must be rejected")
}
