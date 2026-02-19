package router_info

import (
	"bytes"
	"crypto/rand"
	"testing"
	"time"

	"github.com/go-i2p/common/certificate"
	"github.com/go-i2p/common/data"
	"github.com/go-i2p/common/key_certificate"
	"github.com/go-i2p/common/keys_and_cert"
	"github.com/go-i2p/common/router_address"
	"github.com/go-i2p/common/router_identity"
	"github.com/go-i2p/common/signature"
	"github.com/go-i2p/crypto/ed25519"
	elgamal "github.com/go-i2p/crypto/elg"
	"github.com/go-i2p/crypto/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

//
// RouterInfo creation and basic accessors
//

func TestRouterInfoCreation(t *testing.T) {
	ri, err := generateTestRouterInfo(t, time.Now())
	assert.NoError(t, err)
	assert.NotNil(t, ri)
}

func TestRouterInfoPublishedDate(t *testing.T) {
	publishedTime := time.Unix(86400, 0)
	ri, err := generateTestRouterInfo(t, publishedTime)
	require.NoError(t, err)
	assert.Equal(t, publishedTime.Unix(), ri.Published().Time().Unix())
}

func TestRouterInfoRouterIdentity(t *testing.T) {
	ri, err := generateTestRouterInfo(t, time.Now())
	require.NoError(t, err)
	assert.NotNil(t, ri.RouterIdentity())
}

func TestRouterInfoAddresses(t *testing.T) {
	ri, err := generateTestRouterInfo(t, time.Now())
	require.NoError(t, err)
	addresses := ri.RouterAddresses()
	assert.NotNil(t, addresses)
	assert.Greater(t, len(addresses), 0)
}

func TestRouterInfoSignature(t *testing.T) {
	ri, err := generateTestRouterInfo(t, time.Now())
	require.NoError(t, err)
	sig := ri.Signature()
	assert.NotNil(t, sig)
}

func TestRouterInfoPeerSize(t *testing.T) {
	ri, err := generateTestRouterInfo(t, time.Now())
	require.NoError(t, err)
	assert.Equal(t, 0, ri.PeerSize())
	assert.IsType(t, 0, ri.PeerSize())
}

func TestRouterInfoRouterAddressCount(t *testing.T) {
	ri, err := generateTestRouterInfo(t, time.Now())
	require.NoError(t, err)
	count := ri.RouterAddressCount()
	assert.Equal(t, len(ri.RouterAddresses()), count)
}

func TestRouterInfoNetwork(t *testing.T) {
	ri := RouterInfo{}
	assert.Equal(t, "i2p", ri.Network())
}

//
// Serialization tests
//

func TestRouterInfoSerialization(t *testing.T) {
	ri, err := generateTestRouterInfo(t, time.Now())
	require.NoError(t, err)
	b, err := ri.Bytes()
	assert.NoError(t, err)
	assert.NotNil(t, b)
	assert.Greater(t, len(b), 0)
}

func TestRouterInfoString(t *testing.T) {
	t.Run("valid RouterInfo", func(t *testing.T) {
		ri, err := generateTestRouterInfo(t, time.Now())
		require.NoError(t, err)
		str := ri.String()
		assert.Contains(t, str, "RouterIdentity:")
		assert.Contains(t, str, "Published:")
		assert.Contains(t, str, "Signature:")
		assert.NotContains(t, str, "Certificate:")
	})
	t.Run("zero-value RouterInfo", func(t *testing.T) {
		ri := RouterInfo{}
		str := ri.String()
		assert.Contains(t, str, "uninitialized")
	})
	t.Run("nil receiver fields", func(t *testing.T) {
		ri := &RouterInfo{}
		str := ri.String()
		assert.Contains(t, str, "uninitialized")
	})
}

//
// Options and capabilities
//

func TestRouterInfoCapabilities(t *testing.T) {
	ri, err := generateTestRouterInfo(t, time.Now())
	require.NoError(t, err)
	_ = ri.RouterCapabilities() // should not panic
}

func TestRouterInfoVersion(t *testing.T) {
	ri, err := generateTestRouterInfo(t, time.Now())
	require.NoError(t, err)
	version := ri.RouterVersion()
	assert.NotEmpty(t, version)
}

func TestRouterInfoGoodVersion(t *testing.T) {
	ri, err := generateTestRouterInfo(t, time.Now())
	require.NoError(t, err)
	isGood, err := ri.GoodVersion()
	assert.NoError(t, err)
	assert.True(t, isGood)
}

func TestRouterInfoUnCongested(t *testing.T) {
	ri, err := generateTestRouterInfo(t, time.Now())
	require.NoError(t, err)
	assert.True(t, ri.UnCongested())
}

func TestRouterInfoReachable(t *testing.T) {
	ri, err := generateTestRouterInfo(t, time.Now())
	require.NoError(t, err)
	_ = ri.Reachable() // should not panic
}

//
// GoodVersion boundary conditions
//

func TestGoodVersionBoundaries(t *testing.T) {
	tests := []struct {
		name    string
		version string
		good    bool
	}{
		{"below minimum (0.9.57)", "0.9.57", false},
		{"at minimum (0.9.58)", "0.9.58", true},
		{"current version (0.9.64)", "0.9.64", true},
		{"at maximum (0.9.99)", "0.9.99", true},
		{"above maximum (0.9.100)", "0.9.100", false},
		{"invalid format", "1.0.0", false},
		{"not i2p major (1.9.58)", "1.9.58", false},
		{"not i2p minor (0.8.58)", "0.8.58", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parts, err := parseAndValidateVersionString(tt.version)
			if err != nil {
				assert.False(t, tt.good)
				return
			}
			major, err := validateMajorVersion(parts[0], tt.version)
			if err != nil {
				assert.False(t, tt.good)
				return
			}
			minor, err := validateMinorVersion(parts[1], major, tt.version)
			if err != nil {
				assert.False(t, tt.good)
				return
			}
			isValid, _ := validatePatchVersionRange(parts[2], minor, tt.version)
			assert.Equal(t, tt.good, isValid)
		})
	}
}

func TestGoodVersionEdgeCases(t *testing.T) {
	tests := []struct {
		name    string
		version string
		good    bool
		wantErr bool
	}{
		{"version with null byte", "0\x00.9.64", true, false},
		{"empty version", "", false, true},
		{"only dots", "..", false, true},
		{"too many dots", "0.9.64.1", false, true},
		{"negative patch 0.9.-1", "0.9.-1", false, true},
		{"version 0.9.999", "0.9.999", false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parts, err := parseAndValidateVersionString(tt.version)
			if err != nil {
				if !tt.wantErr {
					t.Errorf("unexpected error parsing version: %v", err)
				}
				return
			}
			major, err := validateMajorVersion(parts[0], tt.version)
			if err != nil {
				return
			}
			minor, err := validateMinorVersion(parts[1], major, tt.version)
			if err != nil {
				return
			}
			isValid, _ := validatePatchVersionRange(parts[2], minor, tt.version)
			assert.Equal(t, tt.good, isValid)
		})
	}
}

//
// Router methods (congestion, bandwidth, transport)
//

func TestIsFloodfill(t *testing.T) {
	ri, err := generateTestRouterInfo(t, time.Now())
	require.NoError(t, err)
	assert.IsType(t, false, ri.IsFloodfill())
}

func TestIsMediumCongested(t *testing.T) {
	ri, err := generateTestRouterInfo(t, time.Now())
	require.NoError(t, err)
	assert.False(t, ri.IsMediumCongested())
}

func TestIsHighCongested(t *testing.T) {
	ri, err := generateTestRouterInfo(t, time.Now())
	require.NoError(t, err)
	assert.False(t, ri.IsHighCongested())
}

func TestIsRejectingTunnels(t *testing.T) {
	ri, err := generateTestRouterInfo(t, time.Now())
	require.NoError(t, err)
	assert.False(t, ri.IsRejectingTunnels())
}

func TestSharedBandwidthCategory(t *testing.T) {
	ri, err := generateTestRouterInfo(t, time.Now())
	require.NoError(t, err)
	assert.IsType(t, "", ri.SharedBandwidthCategory())
}

func TestBandwidthTierMethods(t *testing.T) {
	ri, err := generateTestRouterInfo(t, time.Now())
	require.NoError(t, err)
	// Just ensure they don't panic and return booleans
	_ = ri.IsLowBandwidthRouter()
	_ = ri.IsMediumLowBandwidthRouter()
	_ = ri.IsMediumBandwidthRouter()
	_ = ri.IsMediumHighBandwidthRouter()
	_ = ri.IsHighBandwidthRouter()
	_ = ri.IsUnlimitedBandwidthRouter()
}

func TestHasIPv4(t *testing.T) {
	ri, err := generateTestRouterInfo(t, time.Now())
	require.NoError(t, err)
	_ = ri.HasIPv4() // should not panic
}

func TestHasIPv6(t *testing.T) {
	ri, err := generateTestRouterInfo(t, time.Now())
	require.NoError(t, err)
	_ = ri.HasIPv6() // should not panic
}

func TestSupportsNTCP2(t *testing.T) {
	ri, err := generateTestRouterInfo(t, time.Now())
	require.NoError(t, err)
	assert.True(t, ri.SupportsNTCP2())
}

func TestSupportsSSU2(t *testing.T) {
	ri, err := generateTestRouterInfo(t, time.Now())
	require.NoError(t, err)
	assert.False(t, ri.SupportsSSU2())
}

//
// OwnedRouterInfo stub
//

func TestOwnedRouterInfoIsStub(t *testing.T) {
	var payload bytes.Buffer
	sigType, err := data.NewIntegerFromInt(7, 2)
	require.NoError(t, err)
	cryptoType, err := data.NewIntegerFromInt(0, 2)
	require.NoError(t, err)
	payload.Write(*sigType)
	payload.Write(*cryptoType)

	cert, err := certificate.NewCertificateWithType(certificate.CERT_KEY, payload.Bytes())
	require.NoError(t, err)
	keyCert, err := key_certificate.KeyCertificateFromCertificate(cert)
	require.NoError(t, err)

	ri := OwnedRouterInfo(*keyCert)
	assert.Nil(t, ri)
}

//
// AddAddress
//

func TestAddAddressUpdatesSize(t *testing.T) {
	ri, err := generateTestRouterInfo(t, time.Now())
	require.NoError(t, err)

	originalSize := ri.size.Int()
	originalCount := len(ri.addresses)
	assert.Equal(t, originalSize, originalCount)

	options := map[string]string{}
	newAddr, err := router_address.NewRouterAddress(3, <-time.After(1*time.Second), "SSU2", options)
	require.NoError(t, err)

	err = ri.AddAddress(newAddr)
	require.NoError(t, err)

	newSize := ri.size.Int()
	newCount := len(ri.addresses)
	assert.Equal(t, originalCount+1, newCount)
	assert.Equal(t, newSize, newCount)
}

//
// Signature type validation
//

func TestValidateSignatureTypeRange(t *testing.T) {
	tests := []struct {
		name    string
		sigType int
		wantErr bool
	}{
		{"DSA_SHA1 (0)", signature.SIGNATURE_TYPE_DSA_SHA1, false},
		{"ECDSA_P256 (1)", signature.SIGNATURE_TYPE_ECDSA_SHA256_P256, false},
		{"ECDSA_P384 (2)", signature.SIGNATURE_TYPE_ECDSA_SHA384_P384, false},
		{"ECDSA_P521 (3)", signature.SIGNATURE_TYPE_ECDSA_SHA512_P521, false},
		{"RSA_2048 (4)", signature.SIGNATURE_TYPE_RSA_SHA256_2048, false},
		{"RSA_3072 (5)", signature.SIGNATURE_TYPE_RSA_SHA384_3072, false},
		{"RSA_4096 (6)", signature.SIGNATURE_TYPE_RSA_SHA512_4096, false},
		{"Ed25519 (7)", signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519, false},
		{"Ed25519ph (8)", signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519PH, false},
		{"RedDSA (11)", signature.SIGNATURE_TYPE_REDDSA_SHA512_ED25519, false},
		{"GOST_512 (9) reserved", signature.SIGNATURE_TYPE_GOST_R3410_2012_512, true},
		{"GOST_1024 (10) reserved", signature.SIGNATURE_TYPE_GOST_R3410_2012_1024, true},
		{"negative type", -1, true},
		{"type 12 (undefined)", 12, true},
		{"type 50 (undefined)", 50, true},
		{"type 255", 255, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateSignatureType(tt.sigType, nil)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

//
// getCertificateTypeFromIdentity
//

func TestGetCertificateTypeFromIdentity(t *testing.T) {
	ri, err := generateTestRouterInfo(t, time.Now())
	require.NoError(t, err)
	certType, certData, err := getCertificateTypeFromIdentity(ri.router_identity)
	assert.NoError(t, err)
	assert.Equal(t, certificate.CERT_KEY, certType)
	assert.NotNil(t, certData)
}

//
// NewRouterInfo rejects unsupported sig types
//

func TestNewRouterInfoRejectsUnsupportedSigType(t *testing.T) {
	keyPair := generateTestKeyPair(t)
	routerIdentity := assembleTestRouterIdentity(t, keyPair)
	addresses := createTestRouterAddresses(t)
	options := map[string]string{"router.version": "0.9.64"}

	_, err := NewRouterInfo(routerIdentity, time.Now(), addresses, options,
		&keyPair.ed25519PrivKey, signature.SIGNATURE_TYPE_DSA_SHA1)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported signature type")
}

//
// cleanString utility
//

func TestCleanStringNullBytes(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		expect string
	}{
		{"null in middle", "0\x00.9.64", "0.9.64"},
		{"null at start", "\x000.9.64", "0.9.64"},
		{"null at end", "0.9.64\x00", "0.9.64"},
		{"multiple nulls", "\x000\x00.\x009\x00.\x006\x004\x00", "0.9.64"},
		{"no nulls", "0.9.64", "0.9.64"},
		{"only nulls", "\x00\x00\x00", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := cleanString(tt.input)
			assert.Equal(t, tt.expect, result)
		})
	}
}

//
// Direct creation test (from router_info2_test.go)
//

func TestCreateRouterInfo(t *testing.T) {
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
	var _ types.ReceivingPublicKey = elg_pubkey

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

	options := map[string]string{"router.version": "0.9.29"}
	routerAddress, err := router_address.NewRouterAddress(3, <-time.After(1*time.Second), "NTCP2", options)
	if err != nil {
		t.Fatalf("Failed to create router address: %v\n", err)
	}
	routerAddresses := []*router_address.RouterAddress{routerAddress}

	routerInfo, err := NewRouterInfo(routerIdentity, time.Now(), routerAddresses, nil, &ed25519_privkey, signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519)
	if err != nil {
		t.Fatalf("Failed to create router info: %v\n", err)
	}

	t.Run("Serialize and Deserialize RouterInfo", func(t *testing.T) {
		routerInfoBytes, err := routerInfo.Bytes()
		t.Log(len(routerInfoBytes), routerInfo.String(), routerInfoBytes)
		if err != nil {
			t.Fatalf("Failed to write RouterInfo to bytes: %v\n", err)
		}
		_, _, err = ReadRouterInfo(routerInfoBytes)
		if err != nil {
			t.Fatalf("Failed to read routerInfoBytes: %v\n", err)
		}
	})
}

//
// Value receiver consistency
//

func TestReceiverConsistency(t *testing.T) {
	ri, err := generateTestRouterInfo(t, time.Now())
	require.NoError(t, err)
	riVal := *ri

	t.Run("Options on value", func(t *testing.T) {
		m := riVal.Options()
		_ = m
	})
	t.Run("Signature on value", func(t *testing.T) {
		s := riVal.Signature()
		_ = s
	})
	t.Run("Network on value", func(t *testing.T) {
		assert.Equal(t, "i2p", riVal.Network())
	})
	t.Run("String on value", func(t *testing.T) {
		str := riVal.String()
		assert.NotEmpty(t, str)
	})
}
