package keys_and_cert

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"testing"

	"github.com/go-i2p/common/certificate"
	"github.com/go-i2p/common/data"
	"github.com/go-i2p/common/key_certificate"
	"github.com/go-i2p/crypto/curve25519"
	"github.com/go-i2p/crypto/ed25519"
	elgamal "github.com/go-i2p/crypto/elg"
	"github.com/go-i2p/crypto/types"

	"github.com/stretchr/testify/require"
)

// ============================================================================
// Test helpers for building wire data
// ============================================================================

// buildKeyCertPayload creates a KEY certificate payload for the given key types.
func buildKeyCertPayload(sigType, cryptoType int) []byte {
	payload := make([]byte, 4)
	binary.BigEndian.PutUint16(payload[0:2], uint16(sigType))
	binary.BigEndian.PutUint16(payload[2:4], uint16(cryptoType))
	return payload
}

// buildTestKeyCert creates a KEY certificate for the given types.
func buildTestKeyCert(t *testing.T, sigType, cryptoType int) *key_certificate.KeyCertificate {
	t.Helper()
	payload := buildKeyCertPayload(sigType, cryptoType)
	cert, err := certificate.NewCertificateWithType(certificate.CERT_KEY, payload)
	require.NoError(t, err)
	keyCert, err := key_certificate.KeyCertificateFromCertificate(cert)
	require.NoError(t, err)
	return keyCert
}

// buildX25519Ed25519Data creates a valid 384+cert byte slice for X25519+Ed25519.
func buildX25519Ed25519Data(t *testing.T) []byte {
	t.Helper()
	block := make([]byte, KEYS_AND_CERT_DATA_SIZE)

	x25519Key := make([]byte, 32)
	_, err := rand.Read(x25519Key)
	require.NoError(t, err)
	copy(block[0:32], x25519Key)

	ed25519Key := make([]byte, 32)
	_, err = rand.Read(ed25519Key)
	require.NoError(t, err)
	copy(block[KEYS_AND_CERT_DATA_SIZE-32:KEYS_AND_CERT_DATA_SIZE], ed25519Key)

	certPayload := buildKeyCertPayload(key_certificate.KEYCERT_SIGN_ED25519, key_certificate.KEYCERT_CRYPTO_X25519)
	certBytes := []byte{certificate.CERT_KEY}
	lenBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBytes, uint16(len(certPayload)))
	certBytes = append(certBytes, lenBytes...)
	certBytes = append(certBytes, certPayload...)
	return append(block, certBytes...)
}

// buildNullCertData creates a valid 384+3 byte slice for a NULL cert (ElGamal + DSA-SHA1).
func buildNullCertData(t *testing.T) []byte {
	t.Helper()
	block := make([]byte, KEYS_AND_CERT_DATA_SIZE)

	_, err := rand.Read(block[:KEYS_AND_CERT_PUBKEY_SIZE])
	require.NoError(t, err)
	_, err = rand.Read(block[KEYS_AND_CERT_PUBKEY_SIZE:KEYS_AND_CERT_DATA_SIZE])
	require.NoError(t, err)

	nullCert := []byte{0x00, 0x00, 0x00}
	return append(block, nullCert...)
}

// buildElgEd25519Data builds valid wire data for ElGamal+Ed25519.
func buildElgEd25519Data(t *testing.T) []byte {
	t.Helper()
	block := make([]byte, KEYS_AND_CERT_DATA_SIZE)

	_, err := rand.Read(block[:256])
	require.NoError(t, err)
	_, err = rand.Read(block[256:352])
	require.NoError(t, err)
	_, err = rand.Read(block[352:384])
	require.NoError(t, err)

	certPayload := buildKeyCertPayload(key_certificate.KEYCERT_SIGN_ED25519, key_certificate.KEYCERT_CRYPTO_ELG)
	certBytes := []byte{certificate.CERT_KEY}
	lenBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBytes, uint16(len(certPayload)))
	certBytes = append(certBytes, lenBytes...)
	certBytes = append(certBytes, certPayload...)
	return append(block, certBytes...)
}

// ============================================================================
// Helpers for creating valid struct instances
// ============================================================================

// createValidKeyAndCert creates a valid ElGamal+Ed25519 KeysAndCert for testing.
func createValidKeyAndCert(t *testing.T) *KeysAndCert {
	t.Helper()

	ed25519_privkey, err := ed25519.GenerateEd25519Key()
	require.NoError(t, err, "Failed to generate Ed25519 private key")
	ed25519_pubkey_raw, err := ed25519_privkey.Public()
	require.NoError(t, err, "Failed to derive Ed25519 public key")
	ed25519_pubkey, ok := ed25519_pubkey_raw.(types.SigningPublicKey)
	require.True(t, ok, "Failed to get SigningPublicKey from Ed25519 public key")

	var elgamal_privkey elgamal.PrivateKey
	err = elgamal.ElgamalGenerate(&elgamal_privkey.PrivateKey, rand.Reader)
	require.NoError(t, err, "Failed to generate ElGamal private key")

	var elg_pubkey elgamal.ElgPublicKey
	yBytes := elgamal_privkey.PublicKey.Y.Bytes()
	require.LessOrEqual(t, len(yBytes), 256, "ElGamal public key Y too large")
	copy(elg_pubkey[256-len(yBytes):], yBytes)

	var payload bytes.Buffer
	cryptoPublicKeyType, err := data.NewIntegerFromInt(0, 2) // ElGamal
	require.NoError(t, err)
	signingPublicKeyType, err := data.NewIntegerFromInt(7, 2) // Ed25519
	require.NoError(t, err)
	payload.Write(*signingPublicKeyType)
	payload.Write(*cryptoPublicKeyType)

	cert, err := certificate.NewCertificateWithType(certificate.CERT_KEY, payload.Bytes())
	require.NoError(t, err)
	keyCert, err := key_certificate.KeyCertificateFromCertificate(cert)
	require.NoError(t, err)

	pubKeySize := keyCert.CryptoSize()
	sigKeySize := keyCert.SigningPublicKeySize()
	paddingSize := KEYS_AND_CERT_DATA_SIZE - pubKeySize - sigKeySize
	padding := make([]byte, paddingSize)
	_, err = rand.Read(padding)
	require.NoError(t, err)

	keysAndCert, err := NewKeysAndCert(keyCert, elg_pubkey, padding, ed25519_pubkey)
	require.NoError(t, err)

	return keysAndCert
}

// createX25519Ed25519KeysAndCert creates a KeysAndCert with X25519 crypto + Ed25519 signing.
func createX25519Ed25519KeysAndCert(t *testing.T) *KeysAndCert {
	t.Helper()

	ed25519Priv, err := ed25519.GenerateEd25519Key()
	require.NoError(t, err)
	ed25519PubRaw, err := ed25519Priv.Public()
	require.NoError(t, err)
	ed25519Pub, ok := ed25519PubRaw.(types.SigningPublicKey)
	require.True(t, ok)

	x25519Key := make(curve25519.Curve25519PublicKey, 32)
	_, err = rand.Read(x25519Key)
	require.NoError(t, err)

	var payload bytes.Buffer
	sigType, err := data.NewIntegerFromInt(key_certificate.KEYCERT_SIGN_ED25519, 2)
	require.NoError(t, err)
	cryptoType, err := data.NewIntegerFromInt(key_certificate.KEYCERT_CRYPTO_X25519, 2)
	require.NoError(t, err)
	payload.Write(*sigType)
	payload.Write(*cryptoType)

	cert, err := certificate.NewCertificateWithType(certificate.CERT_KEY, payload.Bytes())
	require.NoError(t, err)
	keyCert, err := key_certificate.KeyCertificateFromCertificate(cert)
	require.NoError(t, err)

	pubKeySize := keyCert.CryptoSize()
	sigKeySize := keyCert.SigningPublicKeySize()
	paddingSize := KEYS_AND_CERT_DATA_SIZE - pubKeySize - sigKeySize
	padding := make([]byte, paddingSize)
	_, err = rand.Read(padding)
	require.NoError(t, err)

	kac, err := NewKeysAndCert(keyCert, x25519Key, padding, ed25519Pub)
	require.NoError(t, err)
	return kac
}

// ============================================================================
// Mock types
// ============================================================================

// createDummyKeyCertificate creates a basic ElGamal+Ed25519 KeyCertificate for testing.
func createDummyKeyCertificate(t *testing.T) *key_certificate.KeyCertificate {
	t.Helper()
	var payload bytes.Buffer
	cryptoPublicKeyType, err := data.NewIntegerFromInt(0, 2) // ElGamal
	require.NoError(t, err)
	signingPublicKeyType, err := data.NewIntegerFromInt(7, 2) // Ed25519
	require.NoError(t, err)
	payload.Write(*signingPublicKeyType)
	payload.Write(*cryptoPublicKeyType)

	cert, err := certificate.NewCertificateWithType(certificate.CERT_KEY, payload.Bytes())
	require.NoError(t, err)
	keyCert, err := key_certificate.KeyCertificateFromCertificate(cert)
	require.NoError(t, err)
	return keyCert
}

// createDummyReceivingKey creates a dummy ElGamal public key for testing.
func createDummyReceivingKey() types.ReceivingPublicKey {
	var key elgamal.ElgPublicKey
	for i := range key {
		key[i] = byte(i % 256)
	}
	return key
}

// createDummySigningKey creates a dummy Ed25519 public key for testing.
func createDummySigningKey() types.SigningPublicKey {
	keyData := make([]byte, 32)
	for i := range keyData {
		keyData[i] = byte(i % 256)
	}
	key, _ := ed25519.NewEd25519PublicKey(keyData)
	return key
}

// wrongSizeKey implements types.SigningPublicKey with arbitrary size for testing.
type wrongSizeKey []byte

func (k wrongSizeKey) Bytes() []byte                        { return []byte(k) }
func (k wrongSizeKey) Len() int                             { return len(k) }
func (k wrongSizeKey) NewVerifier() (types.Verifier, error) { return nil, nil }

// createWrongSizeSigningKey creates a 64-byte signing key that
// would be wrong for a certificate declaring Ed25519 (32 bytes).
func createWrongSizeSigningKey() types.SigningPublicKey {
	return wrongSizeKey(make([]byte, 64))
}
