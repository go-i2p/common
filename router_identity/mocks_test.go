package router_identity

import (
	"crypto/rand"
	"encoding/binary"
	"testing"

	"github.com/go-i2p/common/certificate"
	"github.com/go-i2p/common/key_certificate"
	"github.com/go-i2p/common/keys_and_cert"
	"github.com/go-i2p/crypto/types"
	"github.com/stretchr/testify/require"
)

// ============================================================
// Mock types for tests
// ============================================================

type mockPublicKey []byte

func (m mockPublicKey) Len() int                               { return len(m) }
func (m mockPublicKey) Bytes() []byte                          { return []byte(m) }
func (m mockPublicKey) NewEncrypter() (types.Encrypter, error) { return nil, nil }

type mockSigningPublicKey []byte

func (m mockSigningPublicKey) Len() int                             { return len(m) }
func (m mockSigningPublicKey) Bytes() []byte                        { return []byte(m) }
func (m mockSigningPublicKey) NewVerifier() (types.Verifier, error) { return nil, nil }

// ============================================================
// Test helpers
// ============================================================

// createValidKeysAndCert creates a valid KeysAndCert for testing
func createValidKeysAndCert(t *testing.T) *keys_and_cert.KeysAndCert {
	t.Helper()
	riBytes := createValidRouterIdentityBytes(t)
	keysAndCert, _, err := keys_and_cert.ReadKeysAndCert(riBytes)
	require.NoError(t, err, "Failed to create test KeysAndCert")
	return keysAndCert
}

// createValidRouterIdentityBytes creates valid router identity bytes for testing
// Uses DSA-SHA1/ElGamal (deprecated but accepted) for simplicity.
func createValidRouterIdentityBytes(t *testing.T) []byte {
	t.Helper()
	keysData := make([]byte, 384)
	_, err := rand.Read(keysData)
	require.NoError(t, err)
	certData := []byte{
		0x05,       // type = KEY certificate (5)
		0x00, 0x04, // length = 4 bytes
		0x00, 0x00, // sig_type = 0 (DSA-SHA1)
		0x00, 0x00, // crypto_type = 0 (ElGamal)
	}
	return append(keysData, certData...)
}

// buildKeyCertPayload creates a 4-byte key certificate payload with the given types.
func buildKeyCertPayload(sigType, cryptoType int) []byte {
	payload := make([]byte, 4)
	binary.BigEndian.PutUint16(payload[0:2], uint16(sigType))
	binary.BigEndian.PutUint16(payload[2:4], uint16(cryptoType))
	return payload
}

// buildRouterIdentityBytes creates valid wire-format bytes for a RouterIdentity
// with the given signing and crypto key types (using KEY certificate type 5).
func buildRouterIdentityBytes(t *testing.T, sigType, cryptoType int) []byte {
	t.Helper()
	block := make([]byte, keys_and_cert.KEYS_AND_CERT_DATA_SIZE)
	_, err := rand.Read(block)
	require.NoError(t, err)

	certPayload := buildKeyCertPayload(sigType, cryptoType)
	certBytes := []byte{certificate.CERT_KEY}
	lenBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBytes, uint16(len(certPayload)))
	certBytes = append(certBytes, lenBytes...)
	certBytes = append(certBytes, certPayload...)
	return append(block, certBytes...)
}

// buildKeysAndCertForTypes creates a valid KeysAndCert with the given key types
// using the constructor API.
func buildKeysAndCertForTypes(t *testing.T, sigType, cryptoType int) *keys_and_cert.KeysAndCert {
	t.Helper()
	keyCert, err := key_certificate.NewKeyCertificateWithTypes(sigType, cryptoType)
	require.NoError(t, err)

	sigKeySize := keyCert.SigningPublicKeySize()
	cryptoKeySize := keyCert.CryptoSize()

	pubKey := make([]byte, cryptoKeySize)
	_, _ = rand.Read(pubKey)
	sigKey := make([]byte, sigKeySize)
	_, _ = rand.Read(sigKey)
	paddingSize := keys_and_cert.KEYS_AND_CERT_DATA_SIZE - cryptoKeySize - sigKeySize
	var padding []byte
	if paddingSize > 0 {
		padding = make([]byte, paddingSize)
	}
	kac, err := keys_and_cert.NewKeysAndCert(keyCert, mockPublicKey(pubKey), padding, mockSigningPublicKey(sigKey))
	require.NoError(t, err)
	return kac
}

// buildMinimalKacWithTypes creates a KeysAndCert with only the KeyCertificate set,
// sufficient for key type validation. Used for types that can't be fully constructed.
func buildMinimalKacWithTypes(t *testing.T, sigType, cryptoType int) *keys_and_cert.KeysAndCert {
	t.Helper()
	keyCert, err := key_certificate.NewKeyCertificateWithTypes(sigType, cryptoType)
	require.NoError(t, err)
	return &keys_and_cert.KeysAndCert{KeyCertificate: keyCert}
}
