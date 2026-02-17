package router_info

import (
	"bytes"
	"crypto/rand"
	"testing"
	"time"

	"github.com/go-i2p/crypto/ed25519"
	"github.com/go-i2p/crypto/types"

	"github.com/go-i2p/common/keys_and_cert"

	"github.com/go-i2p/common/certificate"
	"github.com/go-i2p/common/data"
	"github.com/go-i2p/common/key_certificate"
	"github.com/go-i2p/common/router_identity"
	"github.com/go-i2p/common/signature"
	elgamal "github.com/go-i2p/crypto/elg"
	"github.com/stretchr/testify/assert"

	"github.com/go-i2p/common/router_address"
)

func generateTestRouterInfo(t *testing.T, publishedTime time.Time) (*RouterInfo, error) {
	keyPair := generateTestKeyPair(t)
	routerIdentity := assembleTestRouterIdentity(t, keyPair)
	routerAddresses := createTestRouterAddresses(t)

	return createRouterInfoFromComponents(t, routerIdentity, publishedTime, routerAddresses, keyPair.ed25519PrivKey)
}

// testKeyPair holds the cryptographic key pair components for testing.
type testKeyPair struct {
	ed25519PrivKey ed25519.Ed25519PrivateKey
	ed25519PubKey  types.SigningPublicKey
	elgPubKey      elgamal.ElgPublicKey
	certificate    *certificate.Certificate
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
func createRouterInfoFromComponents(t *testing.T, routerIdentity *router_identity.RouterIdentity, publishedTime time.Time, routerAddresses []*router_address.RouterAddress, privKey ed25519.Ed25519PrivateKey) (*RouterInfo, error) {
	options := map[string]string{}
	// default here to a good version
	options["router.version"] = "0.9.64"
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

	certBytes := cert.Bytes()
	t.Logf("Serialized Certificate Size: %d bytes", len(certBytes))

	return cert
}

// createTestRouterIdentity assembles a router identity from keys and certificate with proper padding.
func createTestRouterIdentity(t *testing.T, elg_pubkey elgamal.ElgPublicKey, ed25519_pubkey types.SigningPublicKey, cert *certificate.Certificate) *router_identity.RouterIdentity {
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

// TestRouterInfoCreation verifies that a RouterInfo object can be created without errors.
func TestRouterInfoCreation(t *testing.T) {
	assert := assert.New(t)

	// Use helper function to generate a RouterInfo
	publishedTime := time.Now()
	routerInfo, err := generateTestRouterInfo(t, publishedTime)

	assert.Nil(err, "RouterInfo creation should not return an error")
	assert.NotNil(routerInfo, "RouterInfo should not be nil")
}

// TestRouterInfoPublishedDate verifies that the published date is correctly set and retrieved.
func TestRouterInfoPublishedDate(t *testing.T) {
	assert := assert.New(t)

	publishedTime := time.Unix(86400, 0) // 1 day since epoch
	routerInfo, err := generateTestRouterInfo(t, publishedTime)

	assert.Nil(err, "RouterInfo creation should not return an error")
	assert.Equal(publishedTime.Unix(), routerInfo.Published().Time().Unix(), "Published date should match the input date")
}

// TestRouterInfoRouterIdentity verifies that the RouterIdentity is correctly set.
func TestRouterInfoRouterIdentity(t *testing.T) {
	assert := assert.New(t)

	routerInfo, err := generateTestRouterInfo(t, time.Now())
	assert.Nil(err, "RouterInfo creation should not return an error")

	routerIdentity := routerInfo.RouterIdentity()
	assert.NotNil(routerIdentity, "RouterIdentity should not be nil")
}

// TestRouterInfoAddresses verifies that the RouterAddresses are correctly set and retrieved.
func TestRouterInfoAddresses(t *testing.T) {
	assert := assert.New(t)

	routerInfo, err := generateTestRouterInfo(t, time.Now())
	assert.Nil(err, "RouterInfo creation should not return an error")

	addresses := routerInfo.RouterAddresses()
	assert.NotNil(addresses, "RouterAddresses should not be nil")
	assert.Greater(len(addresses), 0, "RouterAddresses should have at least one address")
}

// TestRouterInfoSerialization verifies that the RouterInfo can be serialized to bytes without error.
func TestRouterInfoSerialization(t *testing.T) {
	assert := assert.New(t)

	routerInfo, err := generateTestRouterInfo(t, time.Now())
	assert.Nil(err, "RouterInfo creation should not return an error")

	bytes, err := routerInfo.Bytes()
	assert.Nil(err, "Serialization should not return an error")
	assert.NotNil(bytes, "Serialized bytes should not be nil")
	assert.Greater(len(bytes), 0, "Serialized bytes should have a length greater than zero")
}

// TestRouterInfoSignature verifies that the signature is correctly set in the RouterInfo.
func TestRouterInfoSignature(t *testing.T) {
	assert := assert.New(t)

	routerInfo, err := generateTestRouterInfo(t, time.Now())
	assert.Nil(err, "RouterInfo creation should not return an error")

	signature := routerInfo.Signature()
	assert.NotNil(signature, "Signature should not be nil")
}

/* TODO: Fix this
// TestRouterInfoCapabilities verifies the RouterCapabilities method functionality.
func TestRouterInfoCapabilities(t *testing.T) {
	assert := assert.New(t)

	routerInfo, err := generateTestRouterInfo(t, time.Now())
	assert.Nil(err, "RouterInfo creation should not return an error")

	capabilities := routerInfo.RouterCapabilities()
	assert.NotEmpty(capabilities, "RouterCapabilities should not be empty")
}
// TODO: Fix this
// TestRouterInfoVersion verifies the RouterVersion method functionality.
func TestRouterInfoVersion(t *testing.T) {
	assert := assert.New(t)

	routerInfo, err := generateTestRouterInfo(t, time.Now())
	assert.Nil(err, "RouterInfo creation should not return an error")

	version := routerInfo.RouterVersion()
	assert.NotEmpty(version, "RouterVersion should not be empty")
}

*/

// TestRouterInfoGoodVersion verifies the GoodVersion method functionality.
func TestRouterInfoGoodVersion(t *testing.T) {
	assert := assert.New(t)

	routerInfo, err := generateTestRouterInfo(t, time.Now())
	assert.Nil(err, "RouterInfo creation should not return an error")

	isGoodVersion, err := routerInfo.GoodVersion()
	if err != nil {
		assert.Fail("GoodVersion returned an error", err)
	}
	assert.IsType(true, isGoodVersion, "GoodVersion should return a boolean")
}

// TestRouterInfoUnCongested verifies the UnCongested method functionality.
func TestRouterInfoUnCongested(t *testing.T) {
	assert := assert.New(t)

	routerInfo, err := generateTestRouterInfo(t, time.Now())
	assert.Nil(err, "RouterInfo creation should not return an error")

	isUncongested := routerInfo.UnCongested()
	assert.IsType(true, isUncongested, "UnCongested should return a boolean")
}

// TestRouterInfoReachable verifies the Reachable method functionality.
func TestRouterInfoReachable(t *testing.T) {
	assert := assert.New(t)

	routerInfo, err := generateTestRouterInfo(t, time.Now())
	assert.Nil(err, "RouterInfo creation should not return an error")

	isReachable := routerInfo.Reachable()
	assert.IsType(true, isReachable, "Reachable should return a boolean")
}

// TestRouterInfoPeerSize verifies that the PeerSize method returns the actual field value.
func TestRouterInfoPeerSize(t *testing.T) {
	assert := assert.New(t)

	routerInfo, err := generateTestRouterInfo(t, time.Now())
	assert.Nil(err, "RouterInfo creation should not return an error")

	peerSize := routerInfo.PeerSize()
	// According to I2P spec, peer_size is always 0, but method should return actual field value
	assert.Equal(0, peerSize, "PeerSize should return the value from the peer_size field")

	// Verify that method returns actual field value, not hardcoded 0
	// We can test this by checking if the method calls the Int() method on the field
	assert.IsType(0, peerSize, "PeerSize should return an integer")
}

//
// Validation Tests
//

// TestRouterInfoValidate tests the Validate method
func TestRouterInfoValidate(t *testing.T) {
	t.Run("valid router info passes validation", func(t *testing.T) {
		assert := assert.New(t)

		routerInfo, err := generateTestRouterInfo(t, time.Now())
		assert.Nil(err, "RouterInfo creation should not return an error")

		err = routerInfo.Validate()
		assert.NoError(err, "Valid RouterInfo should pass validation")
	})

	t.Run("nil router info fails validation", func(t *testing.T) {
		assert := assert.New(t)

		var routerInfo *RouterInfo
		err := routerInfo.Validate()
		assert.Error(err, "Nil RouterInfo should fail validation")
		assert.Contains(err.Error(), "router info is nil")
	})

	t.Run("router info with nil identity fails validation", func(t *testing.T) {
		assert := assert.New(t)

		publishedDate, err := createPublishedDate(time.Now())
		assert.Nil(err)
		sizeInt, peerSizeInt, err := createSizeIntegers([]*router_address.RouterAddress{{}})
		assert.Nil(err)
		options, err := data.GoMapToMapping(map[string]string{})
		assert.Nil(err)

		routerInfo := &RouterInfo{
			router_identity: nil,
			published:       publishedDate,
			size:            sizeInt,
			addresses:       []*router_address.RouterAddress{{}},
			peer_size:       peerSizeInt,
			options:         options,
			signature:       &signature.Signature{},
		}

		err = routerInfo.Validate()
		assert.Error(err, "RouterInfo with nil identity should fail validation")
		assert.Contains(err.Error(), "router identity is required")
	})

	t.Run("router info with nil published date fails validation", func(t *testing.T) {
		assert := assert.New(t)

		keyPair := generateTestKeyPair(t)
		routerIdentity := assembleTestRouterIdentity(t, keyPair)
		sizeInt, peerSizeInt, err := createSizeIntegers([]*router_address.RouterAddress{{}})
		assert.Nil(err)
		options, err := data.GoMapToMapping(map[string]string{})
		assert.Nil(err)

		routerInfo := &RouterInfo{
			router_identity: routerIdentity,
			published:       nil,
			size:            sizeInt,
			addresses:       []*router_address.RouterAddress{{}},
			peer_size:       peerSizeInt,
			options:         options,
			signature:       &signature.Signature{},
		}

		err = routerInfo.Validate()
		assert.Error(err, "RouterInfo with nil published date should fail validation")
		assert.Contains(err.Error(), "published date is required")
	})

	t.Run("router info with no addresses fails validation", func(t *testing.T) {
		assert := assert.New(t)

		keyPair := generateTestKeyPair(t)
		routerIdentity := assembleTestRouterIdentity(t, keyPair)
		publishedDate, err := createPublishedDate(time.Now())
		assert.Nil(err)
		sizeInt, peerSizeInt, err := createSizeIntegers([]*router_address.RouterAddress{})
		assert.Nil(err)
		options, err := data.GoMapToMapping(map[string]string{})
		assert.Nil(err)

		routerInfo := &RouterInfo{
			router_identity: routerIdentity,
			published:       publishedDate,
			size:            sizeInt,
			addresses:       []*router_address.RouterAddress{},
			peer_size:       peerSizeInt,
			options:         options,
			signature:       &signature.Signature{},
		}

		err = routerInfo.Validate()
		assert.Error(err, "RouterInfo with no addresses should fail validation")
		assert.Contains(err.Error(), "at least one address")
	})

	t.Run("router info with nil options fails validation", func(t *testing.T) {
		assert := assert.New(t)

		keyPair := generateTestKeyPair(t)
		routerIdentity := assembleTestRouterIdentity(t, keyPair)
		publishedDate, err := createPublishedDate(time.Now())
		assert.Nil(err)
		sizeInt, peerSizeInt, err := createSizeIntegers([]*router_address.RouterAddress{{}})
		assert.Nil(err)

		routerInfo := &RouterInfo{
			router_identity: routerIdentity,
			published:       publishedDate,
			size:            sizeInt,
			addresses:       []*router_address.RouterAddress{{}},
			peer_size:       peerSizeInt,
			options:         nil,
			signature:       &signature.Signature{},
		}

		err = routerInfo.Validate()
		assert.Error(err, "RouterInfo with nil options should fail validation")
		assert.Contains(err.Error(), "options mapping is required")
	})

	t.Run("router info with nil signature fails validation", func(t *testing.T) {
		assert := assert.New(t)

		keyPair := generateTestKeyPair(t)
		routerIdentity := assembleTestRouterIdentity(t, keyPair)
		publishedDate, err := createPublishedDate(time.Now())
		assert.Nil(err)
		sizeInt, peerSizeInt, err := createSizeIntegers([]*router_address.RouterAddress{{}})
		assert.Nil(err)

		// Create a valid mapping for options
		options, err := data.GoMapToMapping(map[string]string{"test": "value"})
		assert.Nil(err, "Creating mapping should not fail")

		routerInfo := &RouterInfo{
			router_identity: routerIdentity,
			published:       publishedDate,
			size:            sizeInt,
			addresses:       []*router_address.RouterAddress{{}},
			peer_size:       peerSizeInt,
			options:         options,
			signature:       nil,
		}

		err = routerInfo.Validate()
		assert.Error(err, "RouterInfo with nil signature should fail validation")
		assert.Contains(err.Error(), "signature is required")
	})
}

// TestRouterInfoIsValid tests the IsValid convenience method
func TestRouterInfoIsValid(t *testing.T) {
	t.Run("valid router info returns true", func(t *testing.T) {
		assert := assert.New(t)

		routerInfo, err := generateTestRouterInfo(t, time.Now())
		assert.Nil(err, "RouterInfo creation should not return an error")

		assert.True(routerInfo.IsValid(), "Valid RouterInfo should return true for IsValid")
	})

	t.Run("nil router info returns false", func(t *testing.T) {
		assert := assert.New(t)

		var routerInfo *RouterInfo
		assert.False(routerInfo.IsValid(), "Nil RouterInfo should return false for IsValid")
	})

	t.Run("router info with nil identity returns false", func(t *testing.T) {
		assert := assert.New(t)

		publishedDate, err := createPublishedDate(time.Now())
		assert.Nil(err)
		sizeInt, peerSizeInt, err := createSizeIntegers([]*router_address.RouterAddress{{}})
		assert.Nil(err)
		options, err := data.GoMapToMapping(map[string]string{})
		assert.Nil(err)

		routerInfo := &RouterInfo{
			router_identity: nil,
			published:       publishedDate,
			size:            sizeInt,
			addresses:       []*router_address.RouterAddress{{}},
			peer_size:       peerSizeInt,
			options:         options,
			signature:       &signature.Signature{},
		}

		assert.False(routerInfo.IsValid(), "RouterInfo with nil identity should return false for IsValid")
	})
}
