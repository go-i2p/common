package encrypted_leaseset

// Tests for the spec DHT key rule: SHA-256(sig type || blinded public key),
// where the sig type is the 2-byte big-endian blinded signing key type.
//
// https://i2p.net/en/docs/specs/encryptedleaseset/ ("Format": "DHT storage
// location is SHA-256(sig type || blinded public key), and rotated daily.")

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/go-i2p/common/data"
	"github.com/go-i2p/crypto/rand"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBlindedDHTKeyMatchesSpecConstruction(t *testing.T) {
	blinded := make([]byte, 32)
	for i := range blinded {
		blinded[i] = byte(i)
	}

	got := BlindedDHTKey(11, blinded)

	// Independent construction: 0x000b || key, SHA-256.
	want := sha256.Sum256(append([]byte{0x00, 0x0b}, blinded...))
	assert.Equal(t, data.Hash(want), got)
}

func TestBlindedDHTKeySigTypeIsPartOfTheKey(t *testing.T) {
	blinded := make([]byte, 32)
	_, _ = rand.Read(blinded)

	// The rule is NOT SHA-256(blinded key) -- hashing the key alone was the
	// previous go-i2p behavior and is invisible to a spec-following floodfill.
	bareKey := data.HashData(blinded)
	assert.NotEqual(t, bareKey, BlindedDHTKey(11, blinded),
		"DHT key must cover the sig type, not just the blinded public key")

	// A different sig type must produce a different key.
	assert.NotEqual(t, BlindedDHTKey(11, blinded), BlindedDHTKey(7, blinded))
}

func TestBlindedDHTKeyKnownVector(t *testing.T) {
	// All-zero blinded key with sig type 11, pinned so a future refactor that
	// changes byte order or silently drops the sig type is caught immediately.
	key := make([]byte, 32)
	got := BlindedDHTKey(11, key)

	want, err := hex.DecodeString("fa3a205e43f49e4af9c0c7b0866dac4f1ae98029b7432aafce8d72f398815370")
	require.NoError(t, err)
	require.Len(t, want, len(got))

	var expected data.Hash
	copy(expected[:], want)
	assert.Equal(t, expected, got, "BlindedDHTKey drifted from SHA-256(0x000b || key)")

	// Little-endian would produce a different hash; pin that too so the byte
	// order is unambiguous.
	le := sha256.Sum256(append([]byte{0x0b, 0x00}, key...))
	assert.NotEqual(t, expected, data.Hash(le), "sig type must be big endian")
}

func TestEncryptedLeaseSetDHTKeyUsesOwnFields(t *testing.T) {
	blinded := make([]byte, 32)
	_, _ = rand.Read(blinded)

	els := EncryptedLeaseSet{sigType: 11, blindedPublicKey: blinded}

	assert.Equal(t, BlindedDHTKey(11, blinded), els.DHTKey())

	// The accessor returns a copy; mutating it must not change the key.
	copied := els.BlindedPublicKey()
	copied[0] ^= 0xFF
	assert.Equal(t, BlindedDHTKey(11, blinded), els.DHTKey())
}
