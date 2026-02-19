package router_info

import (
	"bytes"
	"crypto/rand"
	"testing"
	"time"

	"github.com/go-i2p/crypto/ed25519"
	"github.com/go-i2p/crypto/types"

	"github.com/go-i2p/common/certificate"
	"github.com/go-i2p/common/data"
	"github.com/go-i2p/common/key_certificate"
	"github.com/go-i2p/common/keys_and_cert"
	"github.com/go-i2p/common/router_address"
	"github.com/go-i2p/common/router_identity"
	"github.com/go-i2p/common/signature"
	elgamal "github.com/go-i2p/crypto/elg"
)

// testKeyPair holds the cryptographic key pair components for testing.
type testKeyPair struct {
	ed25519PrivKey ed25519.Ed25519PrivateKey
	ed25519PubKey  types.SigningPublicKey
	elgPubKey      elgamal.ElgPublicKey
	certificate    *certificate.Certificate
}

// generateTestRouterInfo creates a fully valid RouterInfo for testing.
func generateTestRouterInfo(t *testing.T, publishedTime time.Time) (*RouterInfo, error) {
	keyPair := generateTestKeyPair(t)
	routerIdentity := assembleTestRouterIdentity(t, keyPair)
	routerAddresses := createTestRouterAddresses(t)
	return createRouterInfoFromComponents(t, routerIdentity, publishedTime, routerAddresses, keyPair.ed25519PrivKey)
}

// generateTestKeyPair creates all necessary cryptographic components for testing.
func generateTestKeyPair(t *testing.T) testKeyPair {
	ed25519PrivKey, ed25519PubKey := generateEd25519KeyPair(t)
	elgPubKey := generateElGamalKeyPair(t)
	cert := createTestCertificate(t)
	return testKeyPair{
		ed25519PrivKey: ed25519PrivKey,
		ed25519PubKey:  ed25519PubKey,
		elgPubKey:      elgPubKey,
		certificate:    cert,
	}
}

// assembleTestRouterIdentity creates a router identity from the generated key components.
func assembleTestRouterIdentity(t *testing.T, keyPair testKeyPair) *router_identity.RouterIdentity {
	return createTestRouterIdentity(t, keyPair.elgPubKey, keyPair.ed25519PubKey, keyPair.certificate)
}

// createRouterInfoFromComponents assembles the final RouterInfo from all prepared components.
func createRouterInfoFromComponents(
	t *testing.T,
	routerIdentity *router_identity.RouterIdentity,
	publishedTime time.Time,
	routerAddresses []*router_address.RouterAddress,
	privKey ed25519.Ed25519PrivateKey,
) (*RouterInfo, error) {
	options := map[string]string{
		"router.version": "0.9.64",
	}
	routerInfo, err := NewRouterInfo(routerIdentity, publishedTime, routerAddresses, options, &privKey, signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519)
	if err != nil {
		t.Fatalf("Failed to create router info: %v\n", err)
	}
	return routerInfo, nil
}

// generateEd25519KeyPair creates and validates Ed25519 signing keys for testing.
func generateEd25519KeyPair(t *testing.T) (ed25519.Ed25519PrivateKey, types.SigningPublicKey) {
	ed25519_signingprivkey, err := ed25519.GenerateEd25519Key()
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 private key: %v\n", err)
	}
	ed25519_privkey := ed25519_signingprivkey.(ed25519.Ed25519PrivateKey)
	if len(ed25519_privkey) != 64 {
		t.Fatalf("Generated Ed25519 private key has wrong size: got %d, want 64", len(ed25519_privkey))
	}
	ed25519_pubkey, err := ed25519_privkey.Public()
	if err != nil {
		t.Fatalf("Failed to derive Ed25519 public key: %v\n", err)
	}
	return ed25519_privkey, ed25519_pubkey
}

// generateElGamalKeyPair creates ElGamal encryption keys and converts them to I2P format.
func generateElGamalKeyPair(t *testing.T) elgamal.ElgPublicKey {
	var elgamal_privkey elgamal.PrivateKey
	err := elgamal.ElgamalGenerate(&elgamal_privkey.PrivateKey, rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ElGamal private key: %v\n", err)
	}
	var elg_pubkey elgamal.ElgPublicKey
	yBytes := elgamal_privkey.PublicKey.Y.Bytes()
	if len(yBytes) > 256 {
		t.Fatalf("ElGamal public key Y too large")
	}
	copy(elg_pubkey[256-len(yBytes):], yBytes)
	var _ types.ReceivingPublicKey = elg_pubkey
	return elg_pubkey
}

// createTestCertificate builds a key certificate with the required payload for testing.
func createTestCertificate(t *testing.T) *certificate.Certificate {
	var payload bytes.Buffer
	signingPublicKeyType, err := data.NewIntegerFromInt(7, 2)
	if err != nil {
		t.Fatalf("Failed to create signing public key type integer: %v", err)
	}
	cryptoPublicKeyType, err := data.NewIntegerFromInt(0, 2)
	if err != nil {
		t.Fatalf("Failed to create crypto public key type integer: %v", err)
	}
	payload.Write(*signingPublicKeyType)
	payload.Write(*cryptoPublicKeyType)
	cert, err := certificate.NewCertificateWithType(certificate.CERT_KEY, payload.Bytes())
	if err != nil {
		t.Fatalf("Failed to create new certificate: %v\n", err)
	}
	return cert
}

// createTestRouterIdentity assembles a router identity from keys and certificate with proper padding.
func createTestRouterIdentity(
	t *testing.T,
	elg_pubkey elgamal.ElgPublicKey,
	ed25519_pubkey types.SigningPublicKey,
	cert *certificate.Certificate,
) *router_identity.RouterIdentity {
	keyCert, err := key_certificate.KeyCertificateFromCertificate(cert)
	if err != nil {
		log.Fatalf("KeyCertificateFromCertificate failed: %v\n", err)
	}
	pubKeySize := keyCert.CryptoSize()
	sigKeySize := keyCert.SigningPublicKeySize()
	paddingSize := keys_and_cert.KEYS_AND_CERT_DATA_SIZE - pubKeySize - sigKeySize
	padding := make([]byte, paddingSize)
	_, err = rand.Read(padding)
	if err != nil {
		t.Fatalf("Failed to generate random padding: %v\n", err)
	}
	routerIdentity, err := router_identity.NewRouterIdentity(elg_pubkey, ed25519_pubkey, cert, padding)
	if err != nil {
		t.Fatalf("Failed to create router identity: %v\n", err)
	}
	return routerIdentity
}

// createTestRouterAddresses generates dummy router addresses for testing purposes.
func createTestRouterAddresses(t *testing.T) []*router_address.RouterAddress {
	options := map[string]string{}
	routerAddress, err := router_address.NewRouterAddress(3, <-time.After(1*time.Second), "NTCP2", options)
	if err != nil {
		t.Fatalf("Failed to create router address: %v\n", err)
	}
	return []*router_address.RouterAddress{routerAddress}
}

// generateTestRouterInfoForFuzz creates a test RouterInfo without *testing.T.
func generateTestRouterInfoForFuzz() (*RouterInfo, error) {
	// Can't easily create full RouterInfo without *testing.T helpers.
	return nil, nil
}
