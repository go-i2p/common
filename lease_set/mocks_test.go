package lease_set

import (
	"bytes"
	"crypto/rand"
	"testing"
	"time"

	"github.com/go-i2p/common/certificate"
	"github.com/go-i2p/common/data"
	"github.com/go-i2p/common/destination"
	"github.com/go-i2p/common/key_certificate"
	"github.com/go-i2p/common/keys_and_cert"
	"github.com/go-i2p/common/lease"
	"github.com/go-i2p/common/router_address"
	"github.com/go-i2p/common/router_identity"
	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/common/signature"
	"github.com/go-i2p/crypto/ed25519"
	elgamal "github.com/go-i2p/crypto/elg"
	"github.com/go-i2p/crypto/types"
	"github.com/samber/oops"
)

// generateTestRouterInfo creates a full RouterInfo with Ed25519 signing keys
// and ElGamal encryption keys, returning all key material needed for LeaseSet tests.
func generateTestRouterInfo(t *testing.T) (*router_info.RouterInfo, types.ReceivingPublicKey, types.SigningPublicKey, types.SigningPublicKey, types.SigningPublicKey, error) {
	t.Helper()

	// Generate signing key pair (Ed25519)
	var ed25519_privkey ed25519.Ed25519PrivateKey
	ed25519_signingprivkey, err := ed25519.GenerateEd25519Key()
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 private key: %v\n", err)
	}
	ed25519_privkey = ed25519_signingprivkey.(ed25519.Ed25519PrivateKey)

	if len(ed25519_privkey) != 64 {
		t.Fatalf("Generated Ed25519 private key has wrong size: got %d, want 64", len(ed25519_privkey))
	}

	ed25519_pubkey_raw, err := ed25519_privkey.Public()
	if err != nil {
		t.Fatalf("Failed to derive Ed25519 public key: %v\n", err)
	}
	ed25519_pubkey, ok := ed25519_pubkey_raw.(types.SigningPublicKey)
	if !ok {
		t.Fatalf("Failed to get SigningPublicKey from Ed25519 public key")
	}

	// Generate encryption key pair (ElGamal)
	var elgamal_privkey elgamal.PrivateKey
	err = elgamal.ElgamalGenerate(&elgamal_privkey.PrivateKey, rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ElGamal private key: %v\n", err)
	}

	var elg_privkey elgamal.ElgPrivateKey
	xBytes := elgamal_privkey.X.Bytes()
	if len(xBytes) > 256 {
		t.Fatalf("ElGamal private key X too large")
	}
	copy(elg_privkey[256-len(xBytes):], xBytes)

	var elg_pubkey elgamal.ElgPublicKey
	yBytes := elgamal_privkey.PublicKey.Y.Bytes()
	if len(yBytes) > 256 {
		t.Fatalf("ElGamal public key Y too large")
	}
	copy(elg_pubkey[256-len(yBytes):], yBytes)

	var _ types.ReceivingPublicKey = elg_pubkey

	// Create KeyCertificate specifying key types
	var payload bytes.Buffer

	signingPublicKeyType, err := data.NewIntegerFromInt(key_certificate.KEYCERT_SIGN_ED25519, 2)
	if err != nil {
		t.Fatalf("Failed to create signing public key type integer: %v", err)
	}

	cryptoPublicKeyType, err := data.NewIntegerFromInt(key_certificate.KEYCERT_CRYPTO_ELG, 2)
	if err != nil {
		t.Fatalf("Failed to create crypto public key type integer: %v", err)
	}

	payload.Write(*signingPublicKeyType)
	payload.Write(*cryptoPublicKeyType)

	cert, err := certificate.NewCertificateWithType(certificate.CERT_KEY, payload.Bytes())
	if err != nil {
		t.Fatalf("Failed to create new certificate: %v\n", err)
	}

	keyCert, err := key_certificate.KeyCertificateFromCertificate(cert)
	if err != nil {
		t.Fatalf("KeyCertificateFromCertificate failed: %v\n", err)
	}
	pubKeySize := keyCert.CryptoSize()
	sigKeySize := keyCert.SigningPublicKeySize()
	paddingSize := keys_and_cert.KEYS_AND_CERT_DATA_SIZE - (pubKeySize + sigKeySize)
	if paddingSize < 0 {
		t.Fatalf("Padding size is negative: %d", paddingSize)
	}
	padding := make([]byte, paddingSize)
	_, err = rand.Read(padding)
	if err != nil {
		t.Fatalf("Failed to generate random padding: %v\n", err)
	}

	// Create RouterIdentity
	routerIdentity, err := router_identity.NewRouterIdentity(elg_pubkey, ed25519_pubkey, cert, padding)
	if err != nil {
		t.Fatalf("Failed to create router identity: %v\n", err)
	}

	// Create dummy addresses
	options := map[string]string{}
	routerAddress, err := router_address.NewRouterAddress(3, <-time.After(1*time.Second), "NTCP2", options)
	if err != nil {
		t.Fatalf("Failed to create router address: %v\n", err)
	}
	routerAddresses := []*router_address.RouterAddress{routerAddress}

	// Create router info
	routerInfo, err := router_info.NewRouterInfo(routerIdentity, time.Now(), routerAddresses, nil, &ed25519_privkey, signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519)
	if err != nil {
		t.Fatalf("Failed to create router info: %v\n", err)
	}

	// Generate signing key pair for the LeaseSet (Ed25519)
	var leaseSetSigningPrivKey ed25519.Ed25519PrivateKey
	leaseSetSigningPrivkey, err := ed25519.GenerateEd25519Key()
	if err != nil {
		t.Fatalf("Failed to generate lease set Ed25519 private key: %v", err)
	}
	leaseSetSigningPrivKey = leaseSetSigningPrivkey.(ed25519.Ed25519PrivateKey)

	if len(leaseSetSigningPrivKey) != 64 {
		t.Fatalf("Generated Ed25519 private key has wrong size: got %d, want 64", len(leaseSetSigningPrivKey))
	}

	leaseSetSigningPubKeyRaw, err := leaseSetSigningPrivKey.Public()
	if err != nil {
		t.Fatalf("Failed to derive lease set Ed25519 public key: %v", err)
	}

	leaseSetSigningPubKey, ok := leaseSetSigningPubKeyRaw.(types.SigningPublicKey)
	if !ok {
		t.Fatalf("Failed to get lease set SigningPublicKey from Ed25519 public key")
	}

	var identityPrivKey ed25519.Ed25519PrivateKey
	_, err = identityPrivKey.Generate()
	if err != nil {
		t.Fatalf("Failed to generate identity Ed25519 private key: %v", err)
	}

	return routerInfo, elg_pubkey, leaseSetSigningPubKey, &leaseSetSigningPrivKey, &identityPrivKey, nil
}

// createTestLease creates a single lease using the provided RouterInfo for the tunnel gateway hash.
func createTestLease(t *testing.T, index int, routerInfo *router_info.RouterInfo) (*lease.Lease, error) {
	t.Helper()

	identityBytes, err := routerInfo.RouterIdentity().KeysAndCert.Bytes()
	if err != nil {
		return nil, err
	}
	tunnelGatewayHash := types.SHA256(identityBytes)

	expiration := time.Now().Add(time.Hour * time.Duration(index+1))

	testLease, err := lease.NewLease(tunnelGatewayHash, uint32(1000+index), expiration)
	if err != nil {
		return nil, err
	}

	return testLease, nil
}

// generateTestDestination creates a Destination with Ed25519 signing key and
// ElGamal encryption key, returning all key material needed for LeaseSet construction.
func generateTestDestination(t *testing.T) (*destination.Destination, types.ReceivingPublicKey, types.SigningPublicKey, types.SigningPrivateKey, error) {
	t.Helper()

	// Generate client signing key pair (Ed25519)
	var ed25519_privkey ed25519.Ed25519PrivateKey
	ed25519_signingprivkey, err := ed25519.GenerateEd25519Key()
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 private key: %v\n", err)
	}
	ed25519_privkey = ed25519_signingprivkey.(ed25519.Ed25519PrivateKey)

	if len(ed25519_privkey) != 64 {
		t.Fatalf("Generated Ed25519 private key has wrong size: got %d, want 64", len(ed25519_privkey))
	}

	ed25519_pubkey_raw, err := ed25519_privkey.Public()
	if err != nil {
		t.Fatalf("Failed to derive Ed25519 public key: %v\n", err)
	}
	ed25519_pubkey, ok := ed25519_pubkey_raw.(types.SigningPublicKey)
	if !ok {
		t.Fatalf("Failed to get SigningPublicKey from Ed25519 public key")
	}

	// Generate client encryption key pair (ElGamal)
	var elgamal_privkey elgamal.PrivateKey
	err = elgamal.ElgamalGenerate(&elgamal_privkey.PrivateKey, rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ElGamal private key: %v\n", err)
	}

	var elg_pubkey elgamal.ElgPublicKey
	yBytes := elgamal_privkey.PublicKey.Y.Bytes()
	if len(yBytes) > 256 {
		t.Fatalf("ElGamal public key Y too large")
	}
	copy(elg_pubkey[256-len(yBytes):], yBytes)

	// Create KeyCertificate specifying key types
	var payload bytes.Buffer
	cryptoPublicKeyType, err := data.NewIntegerFromInt(0, 2) // ElGamal
	if err != nil {
		t.Fatalf("Failed to create crypto public key type integer: %v", err)
	}

	signingPublicKeyType, err := data.NewIntegerFromInt(7, 2) // Ed25519
	if err != nil {
		t.Fatalf("Failed to create signing public key type integer: %v", err)
	}
	payload.Write(*signingPublicKeyType)
	payload.Write(*cryptoPublicKeyType)

	cert, err := certificate.NewCertificateWithType(certificate.CERT_KEY, payload.Bytes())
	if err != nil {
		t.Fatalf("Failed to create new certificate: %v\n", err)
	}

	keyCert, err := key_certificate.KeyCertificateFromCertificate(cert)
	if err != nil {
		t.Fatalf("Failed to create KeyCertificate from Certificate: %v", err)
	}

	paddingSize := keys_and_cert.KEYS_AND_CERT_DATA_SIZE - (elg_pubkey.Len() + ed25519_pubkey.Len())
	if paddingSize < 0 {
		t.Fatalf("Padding size is negative: %d", paddingSize)
	}
	padding := make([]byte, paddingSize)
	_, err = rand.Read(padding)
	if err != nil {
		t.Fatalf("Failed to generate random padding: %v\n", err)
	}

	kac, err := keys_and_cert.NewKeysAndCert(
		keyCert,
		elg_pubkey,
		padding,
		ed25519_pubkey,
	)
	if err != nil {
		t.Fatalf("Failed to create KeysAndCert: %v", err)
	}

	dest := &destination.Destination{
		KeysAndCert: kac,
	}

	return dest, elg_pubkey, ed25519_pubkey, &ed25519_privkey, nil
}

// createTestLeaseSet creates a complete LeaseSet with the specified number of leases.
func createTestLeaseSet(t *testing.T, routerInfo *router_info.RouterInfo, leaseCount int) (*LeaseSet, error) {
	t.Helper()

	dest, encryptionKey, signingKey, signingPrivKey, err := generateTestDestination(t)
	if err != nil {
		return nil, oops.Errorf("failed to generate test destination: %v", err)
	}

	destBytes, err := dest.KeysAndCert.Bytes()
	if err != nil {
		return nil, oops.Errorf("failed to serialize destination: %v", err)
	}
	t.Logf("Destination size: %d bytes", len(destBytes))

	if len(destBytes) < 387 {
		t.Fatalf("Destination size %d is less than required 387 bytes", len(destBytes))
	}

	var leases []lease.Lease
	for i := 0; i < leaseCount; i++ {
		testLease, err := createTestLease(t, i, routerInfo)
		if err != nil {
			return nil, err
		}
		leases = append(leases, *testLease)
	}

	leaseSet, err := NewLeaseSet(
		*dest,
		encryptionKey,
		signingKey,
		leases,
		signingPrivKey,
	)
	if err != nil {
		t.Logf("Failed to create lease set: %v", err)
	}

	return leaseSet, err
}
