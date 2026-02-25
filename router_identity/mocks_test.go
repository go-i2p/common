package router_identity

import (
	"encoding/binary"
	"testing"

	"github.com/go-i2p/crypto/rand"

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
func createValidKeysAndCert(t testing.TB) *keys_and_cert.KeysAndCert {
	t.Helper()
	riBytes := createValidRouterIdentityBytes(t)
	keysAndCert, _, err := keys_and_cert.ReadKeysAndCert(riBytes)
	require.NoError(t, err, "Failed to create test KeysAndCert")
	return keysAndCert
}

// createValidRouterIdentityBytes creates valid router identity bytes for testing
// Uses DSA-SHA1/ElGamal (deprecated but accepted) for simplicity.
func createValidRouterIdentityBytes(t testing.TB) []byte {
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
func buildRouterIdentityBytes(t testing.TB, sigType, cryptoType int) []byte {
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
// For signing key types larger than KEYS_AND_CERT_SPK_SIZE (e.g. RSA-2048, P521),
// only the first KEYS_AND_CERT_SPK_SIZE bytes of the signing key fit in the inline
// field; the rest go in the cert payload.  Padding is computed accordingly.
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
	// For large signing keys (> SPK slot) only the first SPK_SIZE bytes are inline.
	inlineSigKeySize := sigKeySize
	if inlineSigKeySize > keys_and_cert.KEYS_AND_CERT_SPK_SIZE {
		inlineSigKeySize = keys_and_cert.KEYS_AND_CERT_SPK_SIZE
	}
	paddingSize := keys_and_cert.KEYS_AND_CERT_DATA_SIZE - cryptoKeySize - inlineSigKeySize
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
