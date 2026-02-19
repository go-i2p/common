package encrypted_leaseset

import (
	"crypto/rand"
	"testing"
	"time"

	"github.com/go-i2p/common/key_certificate"
	sig "github.com/go-i2p/common/signature"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ————————————————————————————————————————————————
// Unit tests for ReadEncryptedLeaseSet and accessor methods
// Source: encrypted_leaseset.go
// ————————————————————————————————————————————————

func TestReadEncryptedLeaseSet(t *testing.T) {
	data := createSpecCompliantELS(t, 100, 0)

	els, remainder, err := ReadEncryptedLeaseSet(data)
	require.NoError(t, err, "parse valid spec-compliant ELS")
	assert.Empty(t, remainder)

	assert.Equal(t, uint16(key_certificate.KEYCERT_SIGN_ED25519), els.SigType())
	assert.Len(t, els.BlindedPublicKey(), 32)
	assert.Greater(t, els.Published(), uint32(0))
	assert.Equal(t, uint16(600), els.Expires())
	assert.Equal(t, uint16(0), els.Flags())
	assert.Equal(t, uint16(100), els.InnerLength())
	assert.Len(t, els.EncryptedInnerData(), 100)
	assert.NotNil(t, els.Signature())
}

func TestReadEncryptedLeaseSetWithRemainder(t *testing.T) {
	data := createSpecCompliantELS(t, 100, 0)
	extra := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	data = append(data, extra...)

	_, remainder, err := ReadEncryptedLeaseSet(data)
	require.NoError(t, err)
	assert.Equal(t, extra, remainder, "should return unparsed trailing data")
}

func TestEncryptedLeaseSetFlagChecks(t *testing.T) {
	tests := []struct {
		name        string
		flags       uint16
		wantOffline bool
		wantUnpub   bool
	}{
		{"No flags", 0x0000, false, false},
		{"Offline keys only", ENCRYPTED_LEASESET_FLAG_OFFLINE_KEYS, true, false},
		{"Unpublished only", ENCRYPTED_LEASESET_FLAG_UNPUBLISHED, false, true},
		{"Both", 0x0003, true, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			els := EncryptedLeaseSet{flags: tt.flags}
			assert.Equal(t, tt.wantOffline, els.HasOfflineKeys())
			assert.Equal(t, tt.wantUnpub, els.IsUnpublished())
		})
	}
}

func TestEncryptedLeaseSetExpiration(t *testing.T) {
	tests := []struct {
		name      string
		published uint32
		expires   uint16
		expired   bool
	}{
		{"Far future", uint32(time.Now().Unix() + 3600), 600, false},
		{"Past", uint32(time.Now().Unix() - 10), 5, true},
		{"Just now", uint32(time.Now().Unix()), 1, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			els := EncryptedLeaseSet{published: tt.published, expires: tt.expires}
			assert.Equal(t, tt.expired, els.IsExpired())
		})
	}
}

func TestEncryptedLeaseSetAccessors(t *testing.T) {
	blindedKey := make([]byte, 32)
	_, _ = rand.Read(blindedKey)
	testPublished := uint32(1700000000)
	testExpires := uint16(600)
	testFlags := uint16(0)
	testInnerData := make([]byte, 100)
	_, _ = rand.Read(testInnerData)
	testSig, _, _ := sig.ReadSignature(make([]byte, 64), sig.SIGNATURE_TYPE_EDDSA_SHA512_ED25519)

	els := EncryptedLeaseSet{
		sigType:            key_certificate.KEYCERT_SIGN_ED25519,
		blindedPublicKey:   blindedKey,
		published:          testPublished,
		expires:            testExpires,
		flags:              testFlags,
		innerLength:        uint16(len(testInnerData)),
		encryptedInnerData: testInnerData,
		signature:          testSig,
	}

	assert.Equal(t, uint16(key_certificate.KEYCERT_SIGN_ED25519), els.SigType())
	assert.Equal(t, blindedKey, els.BlindedPublicKey())
	assert.Equal(t, testPublished, els.Published())
	assert.Equal(t, testExpires, els.Expires())
	assert.Equal(t, testFlags, els.Flags())
	assert.Equal(t, uint16(100), els.InnerLength())
	assert.Equal(t, testInnerData, els.EncryptedInnerData())
	assert.Equal(t, testSig, els.Signature())

	// Time conversions
	expectedTime := time.Unix(int64(testPublished), 0).UTC()
	assert.Equal(t, expectedTime, els.PublishedTime())
	expectedExpiration := expectedTime.Add(time.Duration(testExpires) * time.Second)
	assert.Equal(t, expectedExpiration, els.ExpirationTime())
}

func TestEncryptedInnerDataReturnsCopy(t *testing.T) {
	original := []byte{1, 2, 3, 4, 5}
	els := EncryptedLeaseSet{encryptedInnerData: original}
	copy1 := els.EncryptedInnerData()
	copy1[0] = 0xFF
	assert.Equal(t, byte(1), els.encryptedInnerData[0], "internal data must not be mutated")
}

func TestBlindedPublicKeyReturnsCopy(t *testing.T) {
	original := make([]byte, 32)
	_, _ = rand.Read(original)
	els := EncryptedLeaseSet{blindedPublicKey: original}
	copy1 := els.BlindedPublicKey()
	copy1[0] = 0xFF
	assert.NotEqual(t, byte(0xFF), els.blindedPublicKey[0], "internal key must not be mutated")
}

func TestEncryptedLeaseSetBytes(t *testing.T) {
	data := createSpecCompliantELS(t, 100, 0)
	els, _, err := ReadEncryptedLeaseSet(data)
	require.NoError(t, err)

	serialized, err := els.Bytes()
	require.NoError(t, err)

	// Parse the serialized data — should produce identical fields
	els2, _, err := ReadEncryptedLeaseSet(serialized)
	require.NoError(t, err)

	assert.Equal(t, els.SigType(), els2.SigType())
	assert.Equal(t, els.BlindedPublicKey(), els2.BlindedPublicKey())
	assert.Equal(t, els.Published(), els2.Published())
	assert.Equal(t, els.Expires(), els2.Expires())
	assert.Equal(t, els.Flags(), els2.Flags())
	assert.Equal(t, els.InnerLength(), els2.InnerLength())
	assert.Equal(t, els.EncryptedInnerData(), els2.EncryptedInnerData())
}

func TestEncryptedLeaseSetRoundTripDeterministic(t *testing.T) {
	data := createSpecCompliantELS(t, 200, 0)

	els1, _, err := ReadEncryptedLeaseSet(data)
	require.NoError(t, err)

	bytes1, err := els1.Bytes()
	require.NoError(t, err)

	els2, _, err := ReadEncryptedLeaseSet(bytes1)
	require.NoError(t, err)

	bytes2, err := els2.Bytes()
	require.NoError(t, err)

	assert.Equal(t, bytes1, bytes2, "round-trip serialization must be deterministic")
}

func TestEncryptedLeaseSetLargeInnerData(t *testing.T) {
	data := createSpecCompliantELS(t, 1000, 0)

	els, _, err := ReadEncryptedLeaseSet(data)
	require.NoError(t, err)
	assert.Equal(t, uint16(1000), els.InnerLength())
	assert.Len(t, els.EncryptedInnerData(), 1000)

	serialized, err := els.Bytes()
	require.NoError(t, err)

	els2, _, err := ReadEncryptedLeaseSet(serialized)
	require.NoError(t, err)
	assert.Equal(t, uint16(1000), els2.InnerLength())
}
