package destination

import (
	"crypto/rand"
	"encoding/binary"
	"testing"

	"github.com/go-i2p/common/key_certificate"
	"github.com/go-i2p/common/keys_and_cert"

	"github.com/stretchr/testify/require"
)

// ============================================================================
// Helpers for building valid destination wire data
// ============================================================================

// createValidDestinationBytes creates valid destination bytes for testing
// using DSA-SHA1 signing + ElGamal crypto (NULL-equivalent KEY cert).
func createValidDestinationBytes(t *testing.T) []byte {
	t.Helper()

	keysData := make([]byte, 384)
	for i := range keysData {
		keysData[i] = byte(i % 256)
	}

	certData := []byte{
		0x05,       // type = KEY certificate (5)
		0x00, 0x04, // length = 4 bytes
		0x00, 0x00, // sig_type = 0 (DSA-SHA1)
		0x00, 0x00, // crypto_type = 0 (ElGamal)
	}

	return append(keysData, certData...)
}

// createValidKeysAndCert creates a valid KeysAndCert for testing.
func createValidKeysAndCert(t *testing.T) *keys_and_cert.KeysAndCert {
	t.Helper()

	destBytes := createValidDestinationBytes(t)
	keysAndCert, _, err := keys_and_cert.ReadKeysAndCert(destBytes)
	require.NoError(t, err, "Failed to create test KeysAndCert")

	return keysAndCert
}

// createDestinationBytesWithCryptoType creates valid destination bytes with a specific crypto type.
func createDestinationBytesWithCryptoType(t *testing.T, cryptoType int) []byte {
	t.Helper()

	keysData := make([]byte, 384)
	for i := range keysData {
		keysData[i] = byte(i % 256)
	}

	certData := []byte{
		0x05,       // type = KEY certificate (5)
		0x00, 0x04, // length = 4 bytes
		0x00, 0x00, // sig_type = 0 (DSA-SHA1)
		byte(cryptoType >> 8), byte(cryptoType), // crypto_type
	}

	return append(keysData, certData...)
}

// createDestinationBytesWithSigningType creates valid destination bytes with
// a specific signing type and ElGamal crypto type.
func createDestinationBytesWithSigningType(t *testing.T, sigType int) []byte {
	t.Helper()

	keysData := make([]byte, 384)
	for i := range keysData {
		keysData[i] = byte(i % 256)
	}

	sigBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(sigBytes, uint16(sigType))

	certData := []byte{
		0x05,       // type = KEY certificate (5)
		0x00, 0x04, // length = 4 bytes
		sigBytes[0], sigBytes[1], // sig_type
		0x00, 0x00, // crypto_type = 0 (ElGamal)
	}

	return append(keysData, certData...)
}

// createEd25519X25519DestinationBytes creates valid destination bytes with
// Ed25519 signing (type 7) and X25519 encryption (type 4).
func createEd25519X25519DestinationBytes(t *testing.T) []byte {
	t.Helper()

	keysData := make([]byte, 384)
	_, err := rand.Read(keysData)
	require.NoError(t, err)

	certData := []byte{
		0x05,       // type = KEY certificate (5)
		0x00, 0x04, // length = 4 bytes
		0x00, 0x07, // sig_type = 7 (Ed25519)
		0x00, 0x04, // crypto_type = 4 (X25519)
	}

	return append(keysData, certData...)
}

// createDestinationBytesWithExcessSigningKey creates destination bytes
// where the signing public key exceeds the 128-byte default space.
func createDestinationBytesWithExcessSigningKey(t *testing.T, sigType int, excessBytes int) []byte {
	t.Helper()

	keysData := make([]byte, 384)
	_, err := rand.Read(keysData)
	require.NoError(t, err)

	sigBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(sigBytes, uint16(sigType))

	payloadLen := 4 + excessBytes
	excessData := make([]byte, excessBytes)
	_, _ = rand.Read(excessData)

	lenBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBytes, uint16(payloadLen))

	certData := []byte{0x05, lenBytes[0], lenBytes[1]}
	certData = append(certData, sigBytes[0], sigBytes[1])
	certData = append(certData, 0x00, 0x00) // crypto_type = ElGamal
	certData = append(certData, excessData...)

	return append(keysData, certData...)
}

// buildKACWithSigningType creates a KeysAndCert with the given signing type
// for direct validation testing. Returns nil if construction fails.
func buildKACWithSigningType(t *testing.T, sigType int) *keys_and_cert.KeysAndCert {
	t.Helper()
	keyCert, err := key_certificate.NewKeyCertificateWithTypes(
		sigType,
		key_certificate.KEYCERT_CRYPTO_ELG,
	)
	if err != nil {
		t.Logf("cannot construct KeyCertificate with signing type %d: %v", sigType, err)
		return nil
	}
	return &keys_and_cert.KeysAndCert{KeyCertificate: keyCert}
}
