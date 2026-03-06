package lease_set2

import (
	"crypto/ed25519"
	"encoding/binary"
	"testing"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/destination"
	"github.com/go-i2p/common/key_certificate"
	"github.com/go-i2p/common/lease"
	"github.com/go-i2p/common/signature"
	"github.com/stretchr/testify/require"
)

// createTestDestination creates a minimal valid destination for testing
func createTestDestination(t *testing.T, sigType uint16) []byte {
	t.Helper()
	keysData := make([]byte, 384)
	for i := range keysData {
		keysData[i] = byte(i % 256)
	}

	certData := []byte{
		0x05,       // Certificate type = KEY (5)
		0x00, 0x04, // Certificate length = 4 bytes
		0x00, 0x00, // Signing key type (big-endian)
		0x00, 0x00, // Crypto key type = ElGamal (big-endian)
	}
	binary.BigEndian.PutUint16(certData[3:5], sigType)

	return append(keysData, certData...)
}

// createTestDest creates a parsed Destination for testing.
func createTestDest(t *testing.T) destination.Destination {
	t.Helper()
	destData := createTestDestination(t, key_certificate.KEYCERT_SIGN_ED25519)
	dest, _, err := destination.ReadDestination(destData)
	require.NoError(t, err)
	return dest
}

// createTestLease2 creates a valid Lease2 for testing.
func createTestLease2(t *testing.T, index int) *lease.Lease2 {
	t.Helper()
	var hashArray [32]byte
	for i := range hashArray {
		hashArray[i] = byte(index*10 + i)
	}
	l2, err := lease.NewLease2(hashArray, uint32(12345+index), time.Now().Add(10*time.Minute))
	require.NoError(t, err)
	return l2
}

// buildLeaseSet2HeaderData builds the common LeaseSet2 preamble:
// destination + published(4) + expires(2) + flags(2) + empty options(2).
// Callers append encryption keys, leases, and signature as needed.
func buildLeaseSet2HeaderData(t *testing.T, sigType uint16, flags uint16) []byte {
	t.Helper()
	destData := createTestDestination(t, sigType)
	data := destData

	publishedBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(publishedBytes, 1735689600)
	data = append(data, publishedBytes...)

	expiresBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(expiresBytes, 600)
	data = append(data, expiresBytes...)

	flagsBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(flagsBytes, flags)
	data = append(data, flagsBytes...)

	// Empty options
	data = append(data, 0x00, 0x00)
	return data
}

// appendLeaseSet2EncKey appends one X25519 encryption key section to data.
func appendLeaseSet2EncKey(data []byte) []byte {
	data = append(data, 0x01) // 1 key
	keyTypeBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(keyTypeBytes, key_certificate.KEYCERT_CRYPTO_X25519)
	data = append(data, keyTypeBytes...)
	keyLenBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(keyLenBytes, 32)
	data = append(data, keyLenBytes...)
	data = append(data, make([]byte, 32)...)
	return data
}

// appendLeaseSet2Lease appends one Lease2 (hash + tunnelID + endDate) to data.
func appendLeaseSet2Lease(data []byte, index int) []byte {
	hash := make([]byte, 32)
	for j := range hash {
		hash[j] = byte(index*10 + j)
	}
	data = append(data, hash...)
	tunnelID := make([]byte, 4)
	binary.BigEndian.PutUint32(tunnelID, uint32(12345+index))
	data = append(data, tunnelID...)
	endDate := make([]byte, 4)
	binary.BigEndian.PutUint32(endDate, uint32(time.Now().Unix()+600))
	data = append(data, endDate...)
	return data
}

// buildMinimalLeaseSet2Data builds raw LeaseSet2 bytes for parsing tests.
// numLeases controls how many Lease2 structures to include.
func buildMinimalLeaseSet2Data(t *testing.T, sigType uint16, numLeases int, flags uint16) []byte {
	t.Helper()
	data := buildLeaseSet2HeaderData(t, sigType, flags)
	data = appendLeaseSet2EncKey(data)

	// Leases
	data = append(data, byte(numLeases))
	for i := 0; i < numLeases; i++ {
		data = appendLeaseSet2Lease(data, i)
	}

	// Ed25519 signature (64 bytes)
	sigData := make([]byte, signature.EdDSA_SHA512_Ed25519_SIZE)
	for i := range sigData {
		sigData[i] = byte(0xAA)
	}
	data = append(data, sigData...)

	return data
}

// createTestDestWithKey creates a destination with a specific Ed25519 public key
// embedded in the signing key field for signature verification.
func createTestDestWithKey(t *testing.T, pubKey ed25519.PublicKey) destination.Destination {
	t.Helper()
	keysData := make([]byte, 384)
	// Place the Ed25519 public key in the last 32 bytes of the 128-byte signing key field
	// (bytes 256-383 = public key area, Ed25519 key at end = bytes 352-383)
	copy(keysData[352:384], pubKey)

	certData := []byte{
		0x05,       // Certificate type = KEY (5)
		0x00, 0x04, // Certificate length = 4 bytes
		0x00, 0x07, // Signing key type = Ed25519 (7)
		0x00, 0x04, // Crypto key type = X25519 (4)
	}

	data := append(keysData, certData...)
	dest, _, err := destination.ReadDestination(data)
	require.NoError(t, err)
	return dest
}

// buildMappingWithKeys builds a Mapping with the given keys (all values = "v").
func buildMappingWithKeys(t *testing.T, keys []string) common.Mapping {
	t.Helper()
	var payload []byte
	for _, k := range keys {
		payload = append(payload, byte(len(k)))
		payload = append(payload, []byte(k)...)
		payload = append(payload, '=')
		payload = append(payload, 0x01)
		payload = append(payload, 'v')
		payload = append(payload, ';')
	}
	sizeBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(sizeBytes, uint16(len(payload)))
	data := append(sizeBytes, payload...)

	mapping, _, _ := common.ReadMapping(data)
	return mapping
}

// buildLeaseSet2DataWithOptions builds LeaseSet2 wire data including a non-empty options mapping.
func buildLeaseSet2DataWithOptions(t *testing.T) []byte {
	t.Helper()
	// Build header without empty options (trim last 2 bytes)
	data := buildLeaseSet2HeaderData(t, key_certificate.KEYCERT_SIGN_ED25519, 0)
	data = data[:len(data)-2]

	mappingContent := []byte{
		0x01, 'a', '=', 0x01, 'b', ';',
		0x01, 'c', '=', 0x01, 'd', ';',
	}
	mappingSize := make([]byte, 2)
	binary.BigEndian.PutUint16(mappingSize, uint16(len(mappingContent)))
	data = append(data, mappingSize...)
	data = append(data, mappingContent...)

	data = appendLeaseSet2EncKey(data)
	data = append(data, 0x01) // 1 lease
	data = appendLeaseSet2Lease(data, 0)
	data = append(data, make([]byte, signature.EdDSA_SHA512_Ed25519_SIZE)...)
	return data
}
