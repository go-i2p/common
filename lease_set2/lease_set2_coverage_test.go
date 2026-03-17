package lease_set2

import (
	"encoding/binary"
	"testing"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/key_certificate"
	"github.com/go-i2p/common/lease"
	"github.com/go-i2p/common/offline_signature"
	"github.com/go-i2p/common/signature"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Validate: offline signature consistency edge cases --------------------

func TestValidateRejectsOfflineSigWithoutFlag(t *testing.T) {
	// Construct a LeaseSet2 with offline sig present but flag not set (flags=0).
	dest := createTestDest(t)
	offSig := createMinimalOfflineSignature(t)
	encKey := createTestEncryptionKey()
	l := createTestLease2(t, 0)

	ls2 := LeaseSet2{
		destination:      dest,
		flags:            0, // no OFFLINE_KEYS flag
		offlineSignature: &offSig,
		encryptionKeys:   []EncryptionKey{encKey},
		leases:           []lease.Lease2{*l},
	}
	err := ls2.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "OFFLINE_KEYS flag not set")
}

func TestValidateRejectsTooManyEncryptionKeys(t *testing.T) {
	dest := createTestDest(t)
	l := createTestLease2(t, 0)

	keys := make([]EncryptionKey, LEASESET2_MAX_ENCRYPTION_KEYS+1)
	for i := range keys {
		keys[i] = createTestEncryptionKey()
	}

	ls2 := LeaseSet2{
		destination:    dest,
		flags:          0,
		encryptionKeys: keys,
		leases:         []lease.Lease2{*l},
	}
	err := ls2.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "too many encryption keys")
}

// --- Constructor: offline signature flag consistency -----------------------

func TestNewLeaseSet2RejectsOfflineSigWithoutFlag(t *testing.T) {
	dest := createTestDest(t)
	offSig := createMinimalOfflineSignature(t)
	encKey := createTestEncryptionKey()
	l := createTestLease2(t, 0)

	_, err := NewLeaseSet2(
		dest, 1735689600, 600,
		0, // no OFFLINE_KEYS flag
		&offSig,
		emptyMapping(t),
		[]EncryptionKey{encKey},
		[]lease.Lease2{*l},
		nil, // signing key not reached
	)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "OFFLINE_KEYS flag not set")
}

// --- Constructor: too many leases ------------------------------------------

func TestNewLeaseSet2RejectsTooManyLeases(t *testing.T) {
	dest := createTestDest(t)
	encKey := createTestEncryptionKey()

	leases := make([]lease.Lease2, LEASESET2_MAX_LEASES+1)
	for i := range leases {
		l := createTestLease2(t, i)
		leases[i] = *l
	}

	_, err := NewLeaseSet2(
		dest, 1735689600, 600, 0, nil,
		emptyMapping(t),
		[]EncryptionKey{encKey},
		leases,
		nil,
	)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "too many leases")
}

// --- Verify: offline signature chain failures ------------------------------

func TestVerifyRejectsNilOfflineSigWithFlag(t *testing.T) {
	// Create parsed LeaseSet2 with OFFLINE_KEYS flag but nil offlineSignature.
	dest := createTestDest(t)
	encKey := createTestEncryptionKey()
	l := createTestLease2(t, 0)
	sig := createDummySignature(t)

	ls2 := LeaseSet2{
		destination:      dest,
		flags:            LEASESET2_FLAG_OFFLINE_KEYS,
		offlineSignature: nil,
		encryptionKeys:   []EncryptionKey{encKey},
		leases:           []lease.Lease2{*l},
		signature:        sig,
	}
	err := ls2.Verify()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "offline signature is nil")
}

func TestVerifyRejectsInvalidOfflineSignatureChain(t *testing.T) {
	// Build a LeaseSet2 with offline keys flag and a garbage offline signature
	data := buildLeaseSet2HeaderData(t, key_certificate.KEYCERT_SIGN_ED25519, LEASESET2_FLAG_OFFLINE_KEYS)

	// Append a minimal-ish offline signature structure.
	// The real offline sig needs: expires(4) + transientSigType(2) + transientPubKey(32) + signature(64)
	offSigData := make([]byte, 4+2+32+64) // 102 bytes for Ed25519→Ed25519
	binary.BigEndian.PutUint32(offSigData[0:4], uint32(time.Now().Add(24*time.Hour).Unix()))
	binary.BigEndian.PutUint16(offSigData[4:6], uint16(signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519)) // transient sig type
	// Rest is zeros — invalid signature
	data = append(data, offSigData...)

	// Re-add the options mapping (empty) since the header already has it
	// Actually buildLeaseSet2HeaderData already adds empty options, so we need to reconstruct
	// Let me build without the header function to avoid double-options

	// Let me re-use from scratch to avoid confusion:
	destData := createTestDestination(t, key_certificate.KEYCERT_SIGN_ED25519)
	raw := make([]byte, 0, 600)
	raw = append(raw, destData...)

	// published(4) + expires(2) + flags(2)
	publishedBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(publishedBytes, 1735689600)
	raw = append(raw, publishedBytes...)
	expiresBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(expiresBytes, 600)
	raw = append(raw, expiresBytes...)
	flagsBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(flagsBytes, LEASESET2_FLAG_OFFLINE_KEYS)
	raw = append(raw, flagsBytes...)

	// Offline signature: expires(4) + transientSigType(2) + transientPubKey(32) + sig(64) = 102
	raw = append(raw, offSigData...)

	// Empty options
	raw = append(raw, 0x00, 0x00)

	// 1 enc key (X25519)
	raw = appendLeaseSet2EncKey(raw)

	// 1 lease
	raw = append(raw, 0x01)
	raw = appendLeaseSet2Lease(raw, 0)

	// Signature (64 bytes, all 0xAA)
	sigData := make([]byte, signature.EdDSA_SHA512_Ed25519_SIZE)
	for i := range sigData {
		sigData[i] = 0xAA
	}
	raw = append(raw, sigData...)

	ls2, _, err := ReadLeaseSet2(raw)
	require.NoError(t, err, "Parsing should succeed even with garbage offline sig")

	// Now verify should fail due to invalid offline signature chain
	err = ls2.Verify()
	assert.Error(t, err)
}

// --- Parsing: multiple encryption keys ------------------------------------

func TestParseMultipleEncryptionKeys(t *testing.T) {
	data := buildLeaseSet2HeaderData(t, key_certificate.KEYCERT_SIGN_ED25519, 0)

	// 3 encryption keys
	data = append(data, 0x03)

	// Key 1: X25519 (type 4, size 32)
	keyType1 := make([]byte, 2)
	binary.BigEndian.PutUint16(keyType1, key_certificate.KEYCERT_CRYPTO_X25519)
	data = append(data, keyType1...)
	keyLen1 := make([]byte, 2)
	binary.BigEndian.PutUint16(keyLen1, 32)
	data = append(data, keyLen1...)
	data = append(data, make([]byte, 32)...)

	// Key 2: ElGamal (type 0, size 256)
	keyType2 := make([]byte, 2)
	binary.BigEndian.PutUint16(keyType2, key_certificate.KEYCERT_CRYPTO_ELG)
	data = append(data, keyType2...)
	keyLen2 := make([]byte, 2)
	binary.BigEndian.PutUint16(keyLen2, 256)
	data = append(data, keyLen2...)
	data = append(data, make([]byte, 256)...)

	// Key 3: Unknown type (type 999, size 48)
	keyType3 := make([]byte, 2)
	binary.BigEndian.PutUint16(keyType3, 999)
	data = append(data, keyType3...)
	keyLen3 := make([]byte, 2)
	binary.BigEndian.PutUint16(keyLen3, 48)
	data = append(data, keyLen3...)
	data = append(data, make([]byte, 48)...)

	// 1 lease
	data = append(data, 0x01)
	data = appendLeaseSet2Lease(data, 0)

	// Signature (64 bytes)
	data = append(data, make([]byte, signature.EdDSA_SHA512_Ed25519_SIZE)...)

	ls2, _, err := ReadLeaseSet2(data)
	assert.NoError(t, err)
	assert.Equal(t, 3, ls2.EncryptionKeyCount())
	assert.Equal(t, uint16(key_certificate.KEYCERT_CRYPTO_X25519), ls2.EncryptionKeys()[0].KeyType)
	assert.Equal(t, uint16(key_certificate.KEYCERT_CRYPTO_ELG), ls2.EncryptionKeys()[1].KeyType)
	assert.Equal(t, uint16(999), ls2.EncryptionKeys()[2].KeyType)
}

// --- Parsing: truncated encryption key header ------------------------------

func TestParseEncryptionKeyHeaderTruncated(t *testing.T) {
	data := buildLeaseSet2HeaderData(t, key_certificate.KEYCERT_SIGN_ED25519, 0)

	// 1 encryption key but only 2 bytes of header (need 4: keyType + keyLen)
	data = append(data, 0x01)
	data = append(data, 0x00, 0x04) // just key type, no key length

	_, _, err := ReadLeaseSet2(data)
	assert.Error(t, err)
}

func TestParseEncryptionKeyDataTruncated(t *testing.T) {
	data := buildLeaseSet2HeaderData(t, key_certificate.KEYCERT_SIGN_ED25519, 0)

	// 1 encryption key, full header but truncated key data
	data = append(data, 0x01)
	keyType := make([]byte, 2)
	binary.BigEndian.PutUint16(keyType, key_certificate.KEYCERT_CRYPTO_X25519)
	data = append(data, keyType...)
	keyLen := make([]byte, 2)
	binary.BigEndian.PutUint16(keyLen, 32)
	data = append(data, keyLen...)
	// Only 10 bytes of key data instead of 32
	data = append(data, make([]byte, 10)...)

	_, _, err := ReadLeaseSet2(data)
	assert.Error(t, err)
}

// --- Parsing: zero leases --------------------------------------------------

func TestParseLeaseSet2ZeroLeases(t *testing.T) {
	data := buildLeaseSet2HeaderData(t, key_certificate.KEYCERT_SIGN_ED25519, 0)
	data = appendLeaseSet2EncKey(data)
	data = append(data, 0x00) // 0 leases
	// Signature
	data = append(data, make([]byte, signature.EdDSA_SHA512_Ed25519_SIZE)...)

	_, _, err := ReadLeaseSet2(data)
	assert.Error(t, err)
}

func TestParseLeaseSet2TooManyLeases(t *testing.T) {
	data := buildLeaseSet2HeaderData(t, key_certificate.KEYCERT_SIGN_ED25519, 0)
	data = appendLeaseSet2EncKey(data)
	data = append(data, byte(LEASESET2_MAX_LEASES+1)) // 17 leases
	// Need enough lease data
	for i := 0; i < LEASESET2_MAX_LEASES+1; i++ {
		data = appendLeaseSet2Lease(data, i)
	}
	data = append(data, make([]byte, signature.EdDSA_SHA512_Ed25519_SIZE)...)

	_, _, err := ReadLeaseSet2(data)
	assert.Error(t, err)
}

// --- Equals edge cases -----------------------------------------------------

func TestEqualsNilLeftHandSide(t *testing.T) {
	dest := createTestDest(t)
	l := createTestLease2(t, 0)
	encKey := createTestEncryptionKey()

	ls2 := &LeaseSet2{
		destination:    dest,
		encryptionKeys: []EncryptionKey{encKey},
		leases:         []lease.Lease2{*l},
	}

	var nilLs2 *LeaseSet2
	assert.False(t, nilLs2.Equals(ls2))
	assert.False(t, ls2.Equals(nilLs2))
	assert.True(t, nilLs2.Equals(nilLs2))
}

// --- helpers ----------------------------------------------------------------

func createTestEncryptionKey() EncryptionKey {
	return EncryptionKey{
		KeyType: key_certificate.KEYCERT_CRYPTO_X25519,
		KeyLen:  32,
		KeyData: make([]byte, 32),
	}
}

func createMinimalOfflineSignature(t *testing.T) offline_signature.OfflineSignature {
	t.Helper()
	// Build raw offline sig bytes: expires(4) + transientSigType(2) + transientPubKey(32) + sig(64)
	raw := make([]byte, 4+2+32+64)
	binary.BigEndian.PutUint32(raw[0:4], uint32(time.Now().Add(24*time.Hour).Unix()))
	binary.BigEndian.PutUint16(raw[4:6], uint16(signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519))

	offSig, _, err := offline_signature.ReadOfflineSignature(raw, uint16(signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519))
	require.NoError(t, err)
	return offSig
}

func createDummySignature(t *testing.T) signature.Signature {
	t.Helper()
	sigData := make([]byte, signature.EdDSA_SHA512_Ed25519_SIZE)
	for i := range sigData {
		sigData[i] = byte(i)
	}
	sig, err := signature.NewSignatureFromBytes(sigData, signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519)
	require.NoError(t, err)
	return sig
}

func emptyMapping(t *testing.T) common.Mapping {
	return common.Mapping{}
}
