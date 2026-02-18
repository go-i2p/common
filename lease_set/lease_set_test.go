package lease_set

import (
	"bytes"
	"crypto/rand"
	"testing"
	"time"

	"github.com/go-i2p/common/destination"
	"github.com/go-i2p/common/key_certificate"
	"github.com/go-i2p/common/router_address"
	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/common/signature"
	"github.com/go-i2p/crypto/types"
	"github.com/samber/oops"

	"github.com/go-i2p/common/data"
	"github.com/go-i2p/common/keys_and_cert"
	"github.com/go-i2p/crypto/ed25519"
	elgamal "github.com/go-i2p/crypto/elg"

	"github.com/go-i2p/common/certificate"
	"github.com/go-i2p/common/lease"
	"github.com/go-i2p/common/router_identity"
	"github.com/stretchr/testify/assert"
)

func generateTestRouterInfo(t *testing.T) (*router_info.RouterInfo, types.ReceivingPublicKey, types.SigningPublicKey, types.SigningPublicKey, types.SigningPublicKey, error) {
	// Generate signing key pair (Ed25519)
	var ed25519_privkey ed25519.Ed25519PrivateKey
	ed25519_signingprivkey, err := ed25519.GenerateEd25519Key() // Use direct key generation
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 private key: %v\n", err)
	}
	ed25519_privkey = ed25519_signingprivkey.(ed25519.Ed25519PrivateKey) // Store the generated key

	// Verify key size
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

	// Convert elgamal private key to elgamal.ElgPrivateKey
	var elg_privkey elgamal.ElgPrivateKey
	xBytes := elgamal_privkey.X.Bytes()
	if len(xBytes) > 256 {
		t.Fatalf("ElGamal private key X too large")
	}
	copy(elg_privkey[256-len(xBytes):], xBytes)

	// Convert elgamal public key to elgamal.ElgPublicKey
	var elg_pubkey elgamal.ElgPublicKey
	yBytes := elgamal_privkey.PublicKey.Y.Bytes()
	if len(yBytes) > 256 {
		t.Fatalf("ElGamal public key Y too large")
	}
	copy(elg_pubkey[256-len(yBytes):], yBytes)

	// Ensure that elg_pubkey implements crypto.PublicKey interface
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

	kind, err := cert.Type()
	if err != nil {
		t.Fatalf("Failed to read certificate type: %v\n", err)
	}
	certLength, err := cert.Length()
	if err != nil {
		t.Fatalf("Failed to read certificate length: %v\n", err)
	}

	t.Logf("Key Certificate Payload Length: %d bytes", len(payload.Bytes()))
	t.Logf("Certificate Type: %d", kind)
	t.Logf("Certificate Length Field: %d", certLength)
	t.Logf("Certificate Bytes Length: %d", len(cert.Bytes()))
	t.Logf("Certificate Bytes: %d", cert.Bytes())

	if certLength != len(cert.Bytes()) {
		t.Logf("Certificate length (%d) does not match with bytes length (%d)", certLength, cert.Bytes())
	}

	certBytes := cert.Bytes()
	t.Logf("Serialized Certificate Size: %d bytes", len(certBytes))

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
	// create some dummy addresses
	options := map[string]string{}
	routerAddress, err := router_address.NewRouterAddress(3, <-time.After(1*time.Second), "NTCP2", options)
	if err != nil {
		t.Fatalf("Failed to create router address: %v\n", err)
	}
	routerAddresses := []*router_address.RouterAddress{routerAddress}
	// create router info
	routerInfo, err := router_info.NewRouterInfo(routerIdentity, time.Now(), routerAddresses, nil, &ed25519_privkey, signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519)
	if err != nil {
		t.Fatalf("Failed to create router info: %v\n", err)
	}

	// Generate signing key pair for the LeaseSet (Ed25519)
	var leaseSetSigningPrivKey ed25519.Ed25519PrivateKey
	leaseSetSigningPrivkey, err := ed25519.GenerateEd25519Key() // Use direct key generation
	if err != nil {
		t.Fatalf("Failed to generate lease set Ed25519 private key: %v", err)
	}
	leaseSetSigningPrivKey = leaseSetSigningPrivkey.(ed25519.Ed25519PrivateKey) // Store the generated key

	// Verify key size
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

func createTestLease(t *testing.T, index int, routerInfo *router_info.RouterInfo) (*lease.Lease, error) {
	// Use the provided routerInfo instead of generating a new one
	identityBytes, err := routerInfo.RouterIdentity().KeysAndCert.Bytes()
	if err != nil {
		return nil, err
	}
	tunnelGatewayHash := types.SHA256(identityBytes)

	// Create expiration time
	expiration := time.Now().Add(time.Hour * time.Duration(index+1)) // Different times for each lease

	// Create lease
	testLease, err := lease.NewLease(tunnelGatewayHash, uint32(1000+index), expiration)
	if err != nil {
		return nil, err
	}

	return testLease, nil
}

func generateTestDestination(t *testing.T) (*destination.Destination, types.ReceivingPublicKey, types.SigningPublicKey, types.SigningPrivateKey, error) {
	// Generate client signing key pair (Ed25519)
	var ed25519_privkey ed25519.Ed25519PrivateKey
	ed25519_signingprivkey, err := ed25519.GenerateEd25519Key() // Use direct key generation
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 private key: %v\n", err)
	}
	ed25519_privkey = ed25519_signingprivkey.(ed25519.Ed25519PrivateKey) // Store the generated key

	// Verify key size
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

	// Convert ElGamal public key to elgamal.ElgPublicKey
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

	// Create Certificate
	cert, err := certificate.NewCertificateWithType(certificate.CERT_KEY, payload.Bytes())
	if err != nil {
		t.Fatalf("Failed to create new certificate: %v\n", err)
	}

	// Convert Certificate to KeyCertificate
	keyCert, err := key_certificate.KeyCertificateFromCertificate(cert)
	if err != nil {
		t.Fatalf("Failed to create KeyCertificate from Certificate: %v", err)
	}

	// Create padding
	paddingSize := keys_and_cert.KEYS_AND_CERT_DATA_SIZE - (elg_pubkey.Len() + ed25519_pubkey.Len())
	if paddingSize < 0 {
		t.Fatalf("Padding size is negative: %d", paddingSize)
	}
	padding := make([]byte, paddingSize)
	_, err = rand.Read(padding)
	if err != nil {
		t.Fatalf("Failed to generate random padding: %v\n", err)
	}

	// Correctly call NewKeysAndCert with parameters in the right order
	kac, err := keys_and_cert.NewKeysAndCert(
		keyCert,
		elg_pubkey,
		padding,
		ed25519_pubkey,
	)
	t.Logf("Signing Public Key Type: %d", signingPublicKeyType.Int())
	t.Logf("Crypto Public Key Type: %d", cryptoPublicKeyType.Int())
	t.Logf("Expected Signing Public Key Size: %d", keyCert.SigningPublicKeySize())
	t.Logf("Expected Crypto Public Key Size: %d", keyCert.CryptoSize())
	t.Logf("Actual Signing Public Key Size: %d", ed25519_pubkey.Len())
	t.Logf("Actual Crypto Public Key Size: %d", elg_pubkey.Len())
	if err != nil {
		t.Fatalf("Failed to create KeysAndCert: %v", err)
	}

	// Create Destination
	dest := &destination.Destination{
		KeysAndCert: kac,
	}

	return dest, elg_pubkey, ed25519_pubkey, &ed25519_privkey, nil
}

// (*router_info.RouterInfo, crypto.PublicKey, types.SigningPublicKey, types.SigningPublicKey, types.SigningPublicKey, error) {
func createTestLeaseSet(t *testing.T, routerInfo *router_info.RouterInfo, leaseCount int) (*LeaseSet, error) {
	// Generate test Destination and client keys
	dest, encryptionKey, signingKey, signingPrivKey, err := generateTestDestination(t)
	if err != nil {
		return nil, oops.Errorf("failed to generate test destination: %v", err)
	}

	destBytes, err := dest.KeysAndCert.Bytes()
	if err != nil {
		return nil, oops.Errorf("failed to serialize destination: %v", err)
	}
	t.Logf("Destination size: %d bytes", len(destBytes))

	// Ensure the destination size is at least 387 bytes
	if len(destBytes) < 387 {
		t.Fatalf("Destination size %d is less than required 387 bytes", len(destBytes))
	}

	// Create leases using the routerInfo
	var leases []lease.Lease
	for i := 0; i < leaseCount; i++ {
		testLease, err := createTestLease(t, i, routerInfo)
		if err != nil {
			return nil, err
		}
		leases = append(leases, *testLease)
	}

	// Create LeaseSet
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

func TestLeaseSetCreation(t *testing.T) {
	assert := assert.New(t)

	// Generate test router info and keys
	routerInfo, _, _, _, _, err := generateTestRouterInfo(t)
	assert.Nil(err)

	leaseSet, err := createTestLeaseSet(t, routerInfo, 1)
	assert.Nil(err)
	assert.NotNil(leaseSet)

	// Check the size of the LeaseSet's Destination KeysAndCert
	dest := leaseSet.Destination()
	assert.NotNil(dest)

	// Verify individual key sizes
	keysAndCert := dest.KeysAndCert
	pubKeySize := keysAndCert.KeyCertificate.CryptoSize()
	assert.Equal(256, pubKeySize, "CryptoPublicKeySize should be 256 bytes for ElGamal")

	sigKeySize := keysAndCert.KeyCertificate.SigningPublicKeySize()
	assert.Equal(32, sigKeySize, "SigningPublicKeySize should be 32 bytes for Ed25519")
}

func TestLeaseSetValidation(t *testing.T) {
	assert := assert.New(t)

	// Generate test router info and keys
	routerInfo, _, _, _, _, err := generateTestRouterInfo(t)
	assert.Nil(err)

	// Test with too many leases
	_, err = createTestLeaseSet(t, routerInfo, 17)
	assert.NotNil(err)
	assert.Equal("invalid lease set: more than 16 leases", err.Error())
}

func TestLeaseSetValidate(t *testing.T) {
	t.Run("nil lease set", func(t *testing.T) {
		var ls *LeaseSet
		err := ls.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "lease set is nil")
	})

	t.Run("valid lease set", func(t *testing.T) {
		routerInfo, _, _, _, _, err := generateTestRouterInfo(t)
		assert.NoError(t, err)

		leaseSet, err := createTestLeaseSet(t, routerInfo, 3)
		assert.NoError(t, err)
		assert.NotNil(t, leaseSet)

		err = leaseSet.Validate()
		assert.NoError(t, err)
	})

	t.Run("lease set with single lease", func(t *testing.T) {
		routerInfo, _, _, _, _, err := generateTestRouterInfo(t)
		assert.NoError(t, err)

		leaseSet, err := createTestLeaseSet(t, routerInfo, 1)
		assert.NoError(t, err)

		err = leaseSet.Validate()
		assert.NoError(t, err)
	})

	t.Run("lease set with maximum leases", func(t *testing.T) {
		routerInfo, _, _, _, _, err := generateTestRouterInfo(t)
		assert.NoError(t, err)

		leaseSet, err := createTestLeaseSet(t, routerInfo, 16)
		assert.NoError(t, err)

		err = leaseSet.Validate()
		assert.NoError(t, err)
	})
}

func TestLeaseSetIsValid(t *testing.T) {
	t.Run("nil lease set", func(t *testing.T) {
		var ls *LeaseSet
		assert.False(t, ls.IsValid())
	})

	t.Run("valid lease set", func(t *testing.T) {
		routerInfo, _, _, _, _, err := generateTestRouterInfo(t)
		assert.NoError(t, err)

		leaseSet, err := createTestLeaseSet(t, routerInfo, 2)
		assert.NoError(t, err)
		assert.True(t, leaseSet.IsValid())
	})
}

func TestLeaseSetComponents(t *testing.T) {
	assert := assert.New(t)

	// Generate test router info and keys
	routerInfo, _, _, _, _, err := generateTestRouterInfo(t)
	assert.Nil(err)

	// Create the test lease set with 3 leases
	leaseSet, err := createTestLeaseSet(t, routerInfo, 3)
	assert.Nil(err)

	dest := leaseSet.Destination()
	assert.NotNil(dest)

	count := leaseSet.LeaseCount()
	assert.Equal(3, count)

	leases := leaseSet.Leases()
	assert.Equal(3, len(leases))

	pubKey, err := leaseSet.PublicKey()
	assert.Nil(err)
	assert.Equal(LEASE_SET_PUBKEY_SIZE, len(pubKey.Bytes()))

	signKey, err := leaseSet.SigningKey()
	assert.Nil(err)
	assert.NotNil(signKey)
}

func TestExpirations(t *testing.T) {
	assert := assert.New(t)

	// Generate test router info and keys
	routerInfo, _, _, _, _, err := generateTestRouterInfo(t)
	assert.Nil(err)

	// Create the test lease set with 3 leases
	leaseSet, err := createTestLeaseSet(t, routerInfo, 3)
	assert.Nil(err)

	newest, err := leaseSet.NewestExpiration()
	assert.Nil(err)
	assert.NotNil(newest)

	oldest, err := leaseSet.OldestExpiration()
	assert.Nil(err)
	assert.NotNil(oldest)

	assert.True(oldest.Time().Before(newest.Time()) || oldest.Time().Equal(newest.Time()))
}

func TestSignatureVerification(t *testing.T) {
	assert := assert.New(t)

	// Generate test router info and keys
	routerInfo, _, _, _, _, err := generateTestRouterInfo(t)
	assert.Nil(err)

	// Create the test lease set
	leaseSet, err := createTestLeaseSet(t, routerInfo, 1)
	assert.Nil(err)

	sig := leaseSet.Signature()
	assert.NotNil(sig)
}
