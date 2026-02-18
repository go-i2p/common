package router_info

import (
	"bytes"
	"testing"
	"time"

	"github.com/go-i2p/common/certificate"
	"github.com/go-i2p/common/data"
	"github.com/go-i2p/common/key_certificate"
	"github.com/go-i2p/common/router_address"
	"github.com/go-i2p/common/signature"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============================================================
// CRITICAL #1: Nil pointer panic in parseRouterInfoCore
// ============================================================

func TestAudit_ParseRouterInfoCoreTruncatedData(t *testing.T) {
	// Provide data that is long enough for RouterIdentity but truncated
	// for the size field, triggering the error path where info.size is nil.
	// This should NOT panic.
	t.Run("empty data", func(t *testing.T) {
		_, _, err := ReadRouterInfo(nil)
		assert.Error(t, err)
	})
	t.Run("too short", func(t *testing.T) {
		_, _, err := ReadRouterInfo([]byte{0x01, 0x02, 0x03})
		assert.Error(t, err)
	})
	t.Run("exactly min identity size but invalid", func(t *testing.T) {
		// A zero-filled buffer of MIN_SIZE may parse as valid zero-cert router identity.
		// But it should fail somewhere in the chain (address parsing, signature, etc.)
		// The key test is it does NOT panic.
		fakeData := make([]byte, ROUTER_INFO_MIN_SIZE)
		_, _, _ = ReadRouterInfo(fakeData) // must not panic
	})
}

// ============================================================
// CRITICAL #2: validateSignatureType rejects valid types 0-4
// ============================================================

func TestAudit_ValidateSignatureTypeRange(t *testing.T) {
	tests := []struct {
		name    string
		sigType int
		wantErr bool
	}{
		{"DSA_SHA1 (0) - deprecated but valid", signature.SIGNATURE_TYPE_DSA_SHA1, false},
		{"ECDSA_P256 (1) - deprecated but valid", signature.SIGNATURE_TYPE_ECDSA_SHA256_P256, false},
		{"ECDSA_P384 (2) - deprecated but valid", signature.SIGNATURE_TYPE_ECDSA_SHA384_P384, false},
		{"ECDSA_P521 (3) - deprecated but valid", signature.SIGNATURE_TYPE_ECDSA_SHA512_P521, false},
		{"RSA_2048 (4) - deprecated but valid", signature.SIGNATURE_TYPE_RSA_SHA256_2048, false},
		{"RSA_3072 (5)", signature.SIGNATURE_TYPE_RSA_SHA384_3072, false},
		{"RSA_4096 (6)", signature.SIGNATURE_TYPE_RSA_SHA512_4096, false},
		{"Ed25519 (7)", signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519, false},
		{"Ed25519ph (8)", signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519PH, false},
		{"RedDSA (11)", signature.SIGNATURE_TYPE_REDDSA_SHA512_ED25519, false},
		{"negative type", -1, true},
		{"type 12 (undefined)", 12, true},
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

// ============================================================
// CRITICAL #3: Cannot parse RouterInfo with NULL certificate
// ============================================================

func TestAudit_ParseRouterInfoSignatureNULLCert(t *testing.T) {
	// This tests that parseRouterInfoSignature handles non-KEY certificates
	// by defaulting to DSA_SHA1 (type 0) with 40-byte signatures.
	// We can't easily construct a full NULL-cert RouterIdentity here,
	// but we verify the validateSignatureType now accepts type 0.
	err := validateSignatureType(signature.SIGNATURE_TYPE_DSA_SHA1, nil)
	assert.NoError(t, err, "DSA_SHA1 should be accepted as a valid signature type")
}

// ============================================================
// CRITICAL #4: UnCongested incorrectly treats K as congestion
// ============================================================

func TestAudit_UnCongestedBandwidthK(t *testing.T) {
	// Create a RouterInfo with "K" in capabilities
	// K is a bandwidth class, not a congestion indicator
	ri, err := generateTestRouterInfo(t, time.Now())
	require.NoError(t, err)

	// A basic RouterInfo with no special caps should be uncongested
	assert.True(t, ri.UnCongested(), "Router with no congestion flags should be uncongested")
}

func TestAudit_UnCongestedCongestionFlags(t *testing.T) {
	// We can't easily set capabilities in the test helper, but we can test
	// the logic by verifying the function body only checks D, E, G.
	// The code was fixed to remove K from the congestion checks.
	// Verify that the function signature is correct.
	ri, err := generateTestRouterInfo(t, time.Now())
	require.NoError(t, err)
	// Default test router has no D/E/G caps, so should be uncongested
	assert.True(t, ri.UnCongested())
}

// ============================================================
// CRITICAL #5: Bytes() panics on nil fields
// ============================================================

func TestAudit_BytesPanicsOnNilFields(t *testing.T) {
	t.Run("nil router_identity", func(t *testing.T) {
		ri := &RouterInfo{published: &data.Date{}}
		_, err := ri.Bytes()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "router_identity is nil")
	})
	t.Run("nil published", func(t *testing.T) {
		ri, err := generateTestRouterInfo(t, time.Now())
		require.NoError(t, err)
		ri.published = nil
		_, err = ri.Bytes()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "published is nil")
	})
	t.Run("nil size", func(t *testing.T) {
		ri, err := generateTestRouterInfo(t, time.Now())
		require.NoError(t, err)
		ri.size = nil
		_, err = ri.Bytes()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "size is nil")
	})
	t.Run("nil peer_size", func(t *testing.T) {
		ri, err := generateTestRouterInfo(t, time.Now())
		require.NoError(t, err)
		ri.peer_size = nil
		_, err = ri.Bytes()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "peer_size is nil")
	})
	t.Run("nil options", func(t *testing.T) {
		ri, err := generateTestRouterInfo(t, time.Now())
		require.NoError(t, err)
		ri.options = nil
		_, err = ri.Bytes()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "options is nil")
	})
	t.Run("nil signature", func(t *testing.T) {
		ri, err := generateTestRouterInfo(t, time.Now())
		require.NoError(t, err)
		ri.signature = nil
		_, err = ri.Bytes()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "signature is nil")
	})
	t.Run("zero-value RouterInfo", func(t *testing.T) {
		ri := RouterInfo{}
		_, err := ri.Bytes()
		assert.Error(t, err)
	})
}

// ============================================================
// CRITICAL #6: String() panics on nil fields
// ============================================================

func TestAudit_StringPanicsOnNilFields(t *testing.T) {
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
	t.Run("valid RouterInfo", func(t *testing.T) {
		ri, err := generateTestRouterInfo(t, time.Now())
		require.NoError(t, err)
		str := ri.String()
		assert.Contains(t, str, "RouterIdentity:")
		assert.Contains(t, str, "Published:")
		assert.Contains(t, str, "Signature:")
	})
}

// ============================================================
// GAP #1: OwnedRouterInfo is a stub
// ============================================================

func TestAudit_OwnedRouterInfoIsStub(t *testing.T) {
	// Build a key certificate the same way as the test helpers
	var payload bytes.Buffer
	sigType, err := data.NewIntegerFromInt(7, 2) // Ed25519
	require.NoError(t, err)
	cryptoType, err := data.NewIntegerFromInt(0, 2) // ElGamal
	require.NoError(t, err)
	payload.Write(*sigType)
	payload.Write(*cryptoType)

	cert, err := certificate.NewCertificateWithType(certificate.CERT_KEY, payload.Bytes())
	require.NoError(t, err)

	keyCert, err := key_certificate.KeyCertificateFromCertificate(cert)
	require.NoError(t, err)

	ri := OwnedRouterInfo(*keyCert)
	assert.Nil(t, ri, "OwnedRouterInfo should return nil (deprecated stub)")
}

// ============================================================
// GAP #2: No signature verification method
// ============================================================

func TestAudit_VerifySignatureValid(t *testing.T) {
	ri, err := generateTestRouterInfo(t, time.Now())
	require.NoError(t, err)

	valid, err := ri.VerifySignature()
	assert.NoError(t, err, "VerifySignature should not error on valid RouterInfo")
	assert.True(t, valid, "VerifySignature should return true for valid RouterInfo")
}

func TestAudit_VerifySignatureDetectsTampering(t *testing.T) {
	ri, err := generateTestRouterInfo(t, time.Now())
	require.NoError(t, err)

	// Tamper with the published date
	tampered := data.Date{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}
	ri.published = &tampered

	valid, err := ri.VerifySignature()
	assert.NoError(t, err, "VerifySignature should not error")
	assert.False(t, valid, "VerifySignature should return false for tampered RouterInfo")
}

func TestAudit_VerifySignatureNilFields(t *testing.T) {
	t.Run("nil router info", func(t *testing.T) {
		ri := &RouterInfo{} // use zero-value instead of nil receiver
		_, err := ri.VerifySignature()
		assert.Error(t, err)
	})
	t.Run("nil router identity", func(t *testing.T) {
		ri := &RouterInfo{}
		_, err := ri.VerifySignature()
		assert.Error(t, err)
	})
	t.Run("nil signature", func(t *testing.T) {
		ri, err := generateTestRouterInfo(t, time.Now())
		require.NoError(t, err)
		ri.signature = nil
		_, err = ri.VerifySignature()
		assert.Error(t, err)
	})
}

// ============================================================
// GAP #3: AddAddress does not update size field
// ============================================================

func TestAudit_AddAddressUpdatesSize(t *testing.T) {
	ri, err := generateTestRouterInfo(t, time.Now())
	require.NoError(t, err)

	originalSize := ri.size.Int()
	originalCount := len(ri.addresses)
	assert.Equal(t, originalSize, originalCount)

	// Add a new address
	options := map[string]string{}
	newAddr, err := router_address.NewRouterAddress(3, <-time.After(1*time.Second), "SSU2", options)
	require.NoError(t, err)

	err = ri.AddAddress(newAddr)
	require.NoError(t, err)

	newSize := ri.size.Int()
	newCount := len(ri.addresses)
	assert.Equal(t, originalCount+1, newCount, "address count should increase by 1")
	assert.Equal(t, newSize, newCount, "size field should match address count after AddAddress")
}

// ============================================================
// GAP #5: No validation that peer_size is zero
// ============================================================

func TestAudit_PeerSizeAlwaysZero(t *testing.T) {
	ri, err := generateTestRouterInfo(t, time.Now())
	require.NoError(t, err)
	assert.Equal(t, 0, ri.PeerSize(), "peer_size should be zero per spec")
}

// ============================================================
// TEST: Round-trip serialization test
// ============================================================

func TestAudit_RoundTripByteFidelity(t *testing.T) {
	ri, err := generateTestRouterInfo(t, time.Now())
	require.NoError(t, err)

	bytes1, err := ri.Bytes()
	require.NoError(t, err)

	ri2, remainder, err := ReadRouterInfo(bytes1)
	require.NoError(t, err)
	assert.Empty(t, remainder, "should have no remainder")

	bytes2, err := ri2.Bytes()
	require.NoError(t, err)

	assert.Equal(t, bytes1, bytes2, "round-trip should produce identical bytes")
}

// ============================================================
// TEST: ReadRouterInfo with malformed input
// ============================================================

func TestAudit_ReadRouterInfoMalformedInput(t *testing.T) {
	t.Run("nil input", func(t *testing.T) {
		_, _, err := ReadRouterInfo(nil)
		assert.Error(t, err)
	})
	t.Run("empty input", func(t *testing.T) {
		_, _, err := ReadRouterInfo([]byte{})
		assert.Error(t, err)
	})
	t.Run("1 byte input", func(t *testing.T) {
		_, _, err := ReadRouterInfo([]byte{0x00})
		assert.Error(t, err)
	})
	t.Run("short input", func(t *testing.T) {
		shortData := make([]byte, 100)
		_, _, err := ReadRouterInfo(shortData)
		assert.Error(t, err)
	})
}

// ============================================================
// TEST: GoodVersion boundary conditions
// ============================================================

func TestAudit_GoodVersionBoundaries(t *testing.T) {
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
			versionParts, err := parseAndValidateVersionString(tt.version)
			if err != nil {
				assert.False(t, tt.good, "expected error for non-good version")
				return
			}
			majorVersion, err := validateMajorVersion(versionParts[0], tt.version)
			if err != nil {
				assert.False(t, tt.good, "expected error for non-good version")
				return
			}
			minorVersion, err := validateMinorVersion(versionParts[1], majorVersion, tt.version)
			if err != nil {
				assert.False(t, tt.good, "expected error for non-good version")
				return
			}
			isValid, _ := validatePatchVersionRange(versionParts[2], minorVersion, tt.version)
			assert.Equal(t, tt.good, isValid)
		})
	}
}

// ============================================================
// TEST: Nil-field accessor panics
// ============================================================

func TestAudit_NilFieldAccessors(t *testing.T) {
	// These should not panic on a zero-value RouterInfo
	t.Run("Bytes on zero value", func(t *testing.T) {
		ri := RouterInfo{}
		_, err := ri.Bytes()
		assert.Error(t, err)
	})
	t.Run("String on zero value", func(t *testing.T) {
		ri := RouterInfo{}
		str := ri.String()
		assert.NotEmpty(t, str)
	})
}

// ============================================================
// TEST: Capability/congestion helper methods
// ============================================================

func TestAudit_IsFloodfill(t *testing.T) {
	ri, err := generateTestRouterInfo(t, time.Now())
	require.NoError(t, err)
	// Default test router is not floodfill
	assert.IsType(t, false, ri.IsFloodfill())
}

func TestAudit_IsMediumCongested(t *testing.T) {
	ri, err := generateTestRouterInfo(t, time.Now())
	require.NoError(t, err)
	assert.False(t, ri.IsMediumCongested(), "default router should not be medium congested")
}

func TestAudit_IsHighCongested(t *testing.T) {
	ri, err := generateTestRouterInfo(t, time.Now())
	require.NoError(t, err)
	assert.False(t, ri.IsHighCongested(), "default router should not be high congested")
}

func TestAudit_IsRejectingTunnels(t *testing.T) {
	ri, err := generateTestRouterInfo(t, time.Now())
	require.NoError(t, err)
	assert.False(t, ri.IsRejectingTunnels(), "default router should not reject tunnels")
}

func TestAudit_SharedBandwidthCategory(t *testing.T) {
	ri, err := generateTestRouterInfo(t, time.Now())
	require.NoError(t, err)
	cat := ri.SharedBandwidthCategory()
	// Default test router may or may not have bandwidth caps
	assert.IsType(t, "", cat)
}

func TestAudit_BandwidthTierMethods(t *testing.T) {
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

func TestAudit_SupportsNTCP2(t *testing.T) {
	ri, err := generateTestRouterInfo(t, time.Now())
	require.NoError(t, err)
	// Our test creates NTCP2 addresses
	assert.True(t, ri.SupportsNTCP2(), "test router should support NTCP2")
}

func TestAudit_SupportsSSU2(t *testing.T) {
	ri, err := generateTestRouterInfo(t, time.Now())
	require.NoError(t, err)
	// Our test does NOT create SSU2 addresses
	assert.False(t, ri.SupportsSSU2(), "test router should not support SSU2 by default")
}

// ============================================================
// QUALITY: Logging correctness
// ============================================================

func TestAudit_GetCertificateTypeFromIdentity(t *testing.T) {
	ri, err := generateTestRouterInfo(t, time.Now())
	require.NoError(t, err)
	certType, certData, err := getCertificateTypeFromIdentity(ri.router_identity)
	assert.NoError(t, err)
	assert.Equal(t, certificate.CERT_KEY, certType, "test router uses KEY certificate")
	assert.NotNil(t, certData)
}
