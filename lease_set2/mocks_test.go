package lease_set2

import (
	"encoding/binary"
	"testing"
	"time"

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

// buildMinimalLeaseSet2Data builds raw LeaseSet2 bytes for parsing tests.
// numLeases controls how many Lease2 structures to include.
func buildMinimalLeaseSet2Data(t *testing.T, sigType uint16, numLeases int, flags uint16) []byte {
	t.Helper()
	destData := createTestDestination(t, sigType)
	data := destData

	published := uint32(1735689600)
	publishedBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(publishedBytes, published)
	data = append(data, publishedBytes...)

	expires := uint16(600)
	expiresBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(expiresBytes, expires)
	data = append(data, expiresBytes...)

	flagsBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(flagsBytes, flags)
	data = append(data, flagsBytes...)

	// Empty options
	data = append(data, 0x00, 0x00)

	// 1 X25519 encryption key
	data = append(data, 0x01)
	keyTypeBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(keyTypeBytes, key_certificate.KEYCERT_CRYPTO_X25519)
	data = append(data, keyTypeBytes...)
	keyLenBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(keyLenBytes, 32)
	data = append(data, keyLenBytes...)
	data = append(data, make([]byte, 32)...)

	// Leases
	data = append(data, byte(numLeases))
	for i := 0; i < numLeases; i++ {
		hash := make([]byte, 32)
		for j := range hash {
			hash[j] = byte(i*10 + j)
		}
		data = append(data, hash...)
		tunnelID := make([]byte, 4)
		binary.BigEndian.PutUint32(tunnelID, uint32(12345+i))
		data = append(data, tunnelID...)
		endDate := make([]byte, 4)
		binary.BigEndian.PutUint32(endDate, uint32(time.Now().Unix()+600))
		data = append(data, endDate...)
	}

	// Ed25519 signature (64 bytes)
	sigData := make([]byte, signature.EdDSA_SHA512_Ed25519_SIZE)
	for i := range sigData {
		sigData[i] = byte(0xAA)
	}
	data = append(data, sigData...)

	return data
}
