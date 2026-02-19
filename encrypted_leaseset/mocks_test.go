package encrypted_leaseset

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"testing"
	"time"

	"github.com/go-i2p/common/data"
	"github.com/go-i2p/common/destination"
	"github.com/go-i2p/common/key_certificate"
	"github.com/go-i2p/common/lease"
	"github.com/go-i2p/common/lease_set2"
	"github.com/go-i2p/common/offline_signature"
	goi2ped25519 "github.com/go-i2p/crypto/ed25519"
	"github.com/stretchr/testify/require"
	"go.step.sm/crypto/x25519"
)

// ————————————————————————————————————————————————
// Shared test helpers for the encrypted_leaseset package
// ————————————————————————————————————————————————

// createTestEd25519Destination creates a destination with Ed25519 signature type for testing.
func createTestEd25519Destination(t *testing.T) destination.Destination {
	t.Helper()

	publicKey, _, err := goi2ped25519.GenerateEd25519KeyPair()
	require.NoError(t, err, "Failed to generate Ed25519 key pair")

	destBytes := make([]byte, 391)
	_, _ = rand.Read(destBytes[:384])

	// Copy actual Ed25519 public key to the signing key position
	copy(destBytes[352:384], publicKey.Bytes())

	// Certificate: type=KEY(5), length=4, sigtype=Ed25519(7), cryptotype=ElGamal(0)
	destBytes[384] = 0x05
	destBytes[385] = 0x00
	destBytes[386] = 0x04
	destBytes[387] = 0x00
	destBytes[388] = 0x07
	destBytes[389] = 0x00
	destBytes[390] = 0x00

	dest, _, err := destination.ReadDestination(destBytes)
	require.NoError(t, err, "Failed to read destination")
	return dest
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

	_, ed25519SigningPriv, err := goi2ped25519.GenerateEd25519KeyPair()
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

// createTestLeaseSet2ForEncryption creates a minimal valid LeaseSet2 for encryption tests.
// Identical to createTestLeaseSet2 but kept as a separate function to mirror
// the original test structure.
func createTestLeaseSet2ForEncryption(t *testing.T) *lease_set2.LeaseSet2 {
	t.Helper()
	return createTestLeaseSet2(t)
}

// createSpecCompliantELS builds a minimal spec-compliant EncryptedLeaseSet wire blob.
// Wire order: sig_type(2) | blinded_key(32) | published(4) | expires(2) | flags(2) |
//
//	len(2) | encrypted_data(innerLen) | signature(64)
func createSpecCompliantELS(t *testing.T, innerLen int, flags uint16) []byte {
	t.Helper()

	data := make([]byte, 0, 109+innerLen)

	// sig_type = Ed25519 (7)
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, key_certificate.KEYCERT_SIGN_ED25519)
	data = append(data, buf...)

	// blinded_public_key (32 bytes)
	blindedKey := make([]byte, 32)
	_, _ = rand.Read(blindedKey)
	data = append(data, blindedKey...)

	// published (4 bytes)
	buf = make([]byte, 4)
	binary.BigEndian.PutUint32(buf, uint32(time.Now().Unix()))
	data = append(data, buf...)

	// expires (2 bytes) - 600 seconds
	buf = make([]byte, 2)
	binary.BigEndian.PutUint16(buf, 600)
	data = append(data, buf...)

	// flags (2 bytes)
	buf = make([]byte, 2)
	binary.BigEndian.PutUint16(buf, flags)
	data = append(data, buf...)

	// inner_length (2 bytes)
	buf = make([]byte, 2)
	binary.BigEndian.PutUint16(buf, uint16(innerLen))
	data = append(data, buf...)

	// encrypted_data
	encData := make([]byte, innerLen)
	_, _ = rand.Read(encData)
	data = append(data, encData...)

	// signature (64 bytes for Ed25519)
	sigData := make([]byte, 64)
	_, _ = rand.Read(sigData)
	data = append(data, sigData...)

	return data
}

// buildMinimalELS builds a valid minimal EncryptedLeaseSet wire format for fuzz seeding.
func buildMinimalELS(tb testing.TB) []byte {
	tb.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		tb.Fatal(err)
	}

	encData := make([]byte, 80)
	els, err := NewEncryptedLeaseSet(
		uint16(key_certificate.KEYCERT_SIGN_ED25519),
		pub,
		uint32(time.Now().Unix()),
		600,
		0,
		nil,
		encData,
		priv,
	)
	if err != nil {
		tb.Fatal(err)
	}

	serialized, err := els.Bytes()
	if err != nil {
		tb.Fatal(err)
	}
	return serialized
}

// buildMinimalELSWithOfflineFlag builds an EncryptedLeaseSet with offline keys for fuzz seeding.
func buildMinimalELSWithOfflineFlag(tb testing.TB) []byte {
	tb.Helper()
	destPub, destPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		tb.Fatal(err)
	}
	transientPub, transientPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		tb.Fatal(err)
	}

	offlineSig := buildOfflineSignature(tb, destPriv, transientPub)

	encData := make([]byte, 80)
	els, err := NewEncryptedLeaseSet(
		uint16(key_certificate.KEYCERT_SIGN_ED25519),
		destPub,
		uint32(time.Now().Unix()),
		600,
		ENCRYPTED_LEASESET_FLAG_OFFLINE_KEYS,
		&offlineSig,
		encData,
		transientPriv,
	)
	if err != nil {
		tb.Fatal(err)
	}

	serialized, err := els.Bytes()
	if err != nil {
		tb.Fatal(err)
	}
	return serialized
}

// buildOfflineSignature creates an OfflineSignature from a destination private key
// and transient public key, suitable for testing offline key scenarios.
func buildOfflineSignature(tb testing.TB, destPriv ed25519.PrivateKey, transientPub ed25519.PublicKey) offline_signature.OfflineSignature {
	tb.Helper()

	offlineExpires := uint32(time.Now().Add(24 * time.Hour).Unix())

	offlineSigData := make([]byte, 0, 4+2+ed25519.PublicKeySize)
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, offlineExpires)
	offlineSigData = append(offlineSigData, buf...)
	buf = make([]byte, 2)
	binary.BigEndian.PutUint16(buf, uint16(key_certificate.KEYCERT_SIGN_ED25519))
	offlineSigData = append(offlineSigData, buf...)
	offlineSigData = append(offlineSigData, transientPub...)

	offlineSigBytes := ed25519.Sign(destPriv, offlineSigData)

	offlineSig, err := offline_signature.NewOfflineSignature(
		offlineExpires,
		uint16(key_certificate.KEYCERT_SIGN_ED25519),
		transientPub,
		offlineSigBytes,
		uint16(key_certificate.KEYCERT_SIGN_ED25519),
	)
	if err != nil {
		tb.Fatal(err)
	}
	return offlineSig
}
