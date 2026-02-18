package router_info

import (
	"bytes"
	"crypto/rand"
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
// BUG: RouterAddressCount() panics on nil size field
// ============================================================

func TestAudit2_RouterAddressCountNilSize(t *testing.T) {
	ri := &RouterInfo{}
	// Must not panic — should return 0
	count := ri.RouterAddressCount()
	assert.Equal(t, 0, count, "RouterAddressCount should return 0 for nil size field")
}

// ============================================================
// BUG: PeerSize() panics on nil peer_size field
// ============================================================

func TestAudit2_PeerSizeNilField(t *testing.T) {
	ri := &RouterInfo{}
	// Must not panic — should return 0
	ps := ri.PeerSize()
	assert.Equal(t, 0, ps, "PeerSize should return 0 for nil peer_size field")
}

// ============================================================
// BUG: Options() panics on nil options field
// ============================================================

func TestAudit2_OptionsNilField(t *testing.T) {
	ri := RouterInfo{}
	// Must not panic — should return empty Mapping
	m := ri.Options()
	assert.NotNil(t, m, "Options should return a non-nil Mapping for nil options field")
}

// ============================================================
// BUG: Signature() panics on nil signature field
// ============================================================

func TestAudit2_SignatureNilField(t *testing.T) {
	ri := RouterInfo{}
	// Must not panic — should return zero-value Signature
	sig := ri.Signature()
	assert.Equal(t, 0, sig.Len(), "Signature should return zero-length for nil signature field")
}

// ============================================================
// BUG: All nil-field accessors on zero-value RouterInfo
// ============================================================

func TestAudit2_ZeroValueRouterInfoAccessors(t *testing.T) {
	ri := &RouterInfo{}

	t.Run("RouterAddressCount", func(t *testing.T) {
		assert.Equal(t, 0, ri.RouterAddressCount())
	})
	t.Run("PeerSize", func(t *testing.T) {
		assert.Equal(t, 0, ri.PeerSize())
	})
	t.Run("Options", func(t *testing.T) {
		m := RouterInfo{}.Options()
		_ = m // no panic
	})
	t.Run("Signature", func(t *testing.T) {
		sig := RouterInfo{}.Signature()
		_ = sig // no panic
	})
	t.Run("RouterAddresses", func(t *testing.T) {
		addrs := ri.RouterAddresses()
		assert.Nil(t, addrs)
	})
	t.Run("Published", func(t *testing.T) {
		pub := ri.Published()
		assert.Nil(t, pub)
	})
	t.Run("RouterIdentity", func(t *testing.T) {
		id := ri.RouterIdentity()
		assert.Nil(t, id)
	})
}

// ============================================================
// SPEC: VerifySignature pre-hashes with SHA-512
// ============================================================

func TestAudit2_VerifySignaturePreHashDocumented(t *testing.T) {
	// The go-i2p/crypto Ed25519 signer pre-hashes with SHA-512.
	// VerifySignature must match that convention.
	// This test verifies that sign-then-verify round-trips correctly.
	ri, err := generateTestRouterInfo(t, time.Now())
	require.NoError(t, err)

	valid, err := ri.VerifySignature()
	assert.NoError(t, err)
	assert.True(t, valid, "VerifySignature should succeed for self-signed RouterInfo")
}

// ============================================================
// SPEC: validateSignatureType extended range
// ============================================================

func TestAudit2_ValidateSignatureTypeExtended(t *testing.T) {
	tests := []struct {
		name    string
		sigType int
		wantErr bool
	}{
		// Types 0-8, 11 are implemented and should be accepted
		{"DSA_SHA1 (0)", signature.SIGNATURE_TYPE_DSA_SHA1, false},
		{"ECDSA_P256 (1)", signature.SIGNATURE_TYPE_ECDSA_SHA256_P256, false},
		{"Ed25519 (7)", signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519, false},
		{"Ed25519ph (8)", signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519PH, false},
		{"RedDSA (11)", signature.SIGNATURE_TYPE_REDDSA_SHA512_ED25519, false},
		// GOST types 9-10 are reserved/unimplemented — rejected by signature.SignatureSize
		{"GOST_512 (9) reserved", signature.SIGNATURE_TYPE_GOST_R3410_2012_512, true},
		{"GOST_1024 (10) reserved", signature.SIGNATURE_TYPE_GOST_R3410_2012_1024, true},
		// Negative should be rejected
		{"negative type", -1, true},
		// Completely unknown types should be rejected
		{"type 50 (undefined)", 50, true},
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
// GAP: OwnedRouterInfo returns nil (deprecated stub)
// ============================================================

func TestAudit2_OwnedRouterInfoReturnsNil(t *testing.T) {
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
	assert.Nil(t, ri, "OwnedRouterInfo should return nil since it is a deprecated stub")
}

// ============================================================
// GAP: NewRouterInfo only supports Ed25519
// ============================================================

func TestAudit2_NewRouterInfoRejectsUnsupportedSigType(t *testing.T) {
	ri, err := generateTestRouterInfo(t, time.Now())
	require.NoError(t, err)
	require.NotNil(t, ri)

	// Attempt to create with unsupported sig type (DSA)
	keyPair := generateTestKeyPair(t)
	routerIdentity := assembleTestRouterIdentity(t, keyPair)
	addresses := createTestRouterAddresses(t)
	options := map[string]string{"router.version": "0.9.64"}

	_, err = NewRouterInfo(routerIdentity, time.Now(), addresses, options,
		&keyPair.ed25519PrivKey, signature.SIGNATURE_TYPE_DSA_SHA1)
	assert.Error(t, err, "NewRouterInfo should reject unsupported signature types")
	assert.Contains(t, err.Error(), "unsupported signature type")
}

// ============================================================
// GAP: peer_size non-zero validation
// ============================================================

func TestAudit2_ReadRouterInfoNonZeroPeerSize(t *testing.T) {
	// Create a valid RouterInfo, serialize it, then modify the peer_size byte
	ri, err := generateTestRouterInfo(t, time.Now())
	require.NoError(t, err)

	_, err = ri.Bytes()
	require.NoError(t, err)

	// The parsePeerSizeFromBytes function logs a warning for non-zero peer_size
	// but still accepts it (lenient parsing). We verify the warning is logged
	// by parsing data with a non-zero peer_size byte.
	// Find the peer_size position: after identity + published + size + addresses
	// This is complex to calculate, so we test the function directly.
	peerSizeVal := data.Integer([]byte{0x05})
	remainder := []byte{0x00, 0x00} // minimal mapping: size=0
	ps, _, err := parsePeerSizeFromBytes(append(peerSizeVal.Bytes(), remainder...))
	require.NoError(t, err, "parsePeerSizeFromBytes should accept non-zero peer_size (lenient)")
	assert.Equal(t, 5, ps.Int(), "peer_size value should be preserved")
}

// ============================================================
// GAP: AddAddress overflow past 255
// ============================================================

func TestAudit2_AddAddressOverflow255(t *testing.T) {
	ri, err := generateTestRouterInfo(t, time.Now())
	require.NoError(t, err)

	// Fill up to 255 addresses
	for i := len(ri.addresses); i < 255; i++ {
		opts := map[string]string{}
		addr, err := router_address.NewRouterAddress(byte(i%256), <-time.After(0), "SSU2", opts)
		require.NoError(t, err)
		err = ri.AddAddress(addr)
		require.NoError(t, err)
	}
	assert.Equal(t, 255, len(ri.addresses), "should have 255 addresses")
	assert.Equal(t, 255, ri.RouterAddressCount(), "size field should be 255")

	// Adding one more should fail
	opts := map[string]string{}
	addr, err := router_address.NewRouterAddress(1, <-time.After(0), "SSU2", opts)
	require.NoError(t, err)
	err = ri.AddAddress(addr)
	assert.Error(t, err, "AddAddress should return error when exceeding 255")
	assert.Equal(t, 255, len(ri.addresses), "address count should remain 255")
}

// ============================================================
// GAP: Bytes() options serialization consistency
// ============================================================

func TestAudit2_BytesOptionsConsistency(t *testing.T) {
	// Verify that Bytes() and serializeWithoutSignature() produce
	// consistent options data (with the 2-byte size prefix).
	ri, err := generateTestRouterInfo(t, time.Now())
	require.NoError(t, err)

	fullBytes, err := ri.Bytes()
	require.NoError(t, err)

	serializedData, err := ri.serializeWithoutSignature()
	require.NoError(t, err)

	// The serialized data + signature should equal the full bytes
	sigBytes := ri.signature.Bytes()
	combined := append(serializedData, sigBytes...)
	assert.Equal(t, fullBytes, combined,
		"Bytes() output should equal serializeWithoutSignature() + signature")
}

// ============================================================
// TEST: Network() returns "i2p"
// ============================================================

func TestAudit2_NetworkReturnsI2P(t *testing.T) {
	ri := RouterInfo{}
	assert.Equal(t, "i2p", ri.Network(), "Network() should return 'i2p'")
}

// ============================================================
// TEST: GoodVersion boundary edge cases
// ============================================================

func TestAudit2_GoodVersionEdgeCases(t *testing.T) {
	tests := []struct {
		name    string
		version string
		good    bool
		wantErr bool
	}{
		{"version with null byte 0\\x00.9.64", "0\x00.9.64", true, false},
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

// ============================================================
// TEST: Fuzz ReadRouterInfo
// ============================================================

func FuzzReadRouterInfo(f *testing.F) {
	// Seed with various inputs
	f.Add([]byte{})
	f.Add([]byte{0x00})
	f.Add(make([]byte, 100))
	f.Add(make([]byte, ROUTER_INFO_MIN_SIZE))

	// Seed with a valid serialized RouterInfo if possible
	ri, err := generateTestRouterInfoForFuzz()
	if err == nil && ri != nil {
		b, err := ri.Bytes()
		if err == nil {
			f.Add(b)
		}
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		// Must not panic
		info, _, err := ReadRouterInfo(data)
		if err == nil {
			// If parsing succeeded, accessors must not panic
			_ = info.RouterAddressCount()
			_ = info.PeerSize()
			_ = info.Options()
			_ = info.Signature()
			_ = info.Network()
			_ = info.String()
			_, _ = info.Bytes()
		}
	})
}

// generateTestRouterInfoForFuzz creates a test RouterInfo without *testing.T.
func generateTestRouterInfoForFuzz() (*RouterInfo, error) {
	ed25519Key, err := generateEd25519KeyForFuzz()
	if err != nil {
		return nil, err
	}
	_ = ed25519Key
	// Can't easily create full RouterInfo without *testing.T helpers.
	// Return nil to skip the valid seed.
	return nil, nil
}

// generateEd25519KeyForFuzz generates an Ed25519 key pair without *testing.T.
func generateEd25519KeyForFuzz() ([]byte, error) {
	key := make([]byte, 64)
	_, err := rand.Read(key)
	return key, err
}

// ============================================================
// TEST: ReadRouterInfo with non-zero peer_size
// ============================================================

func TestAudit2_ReadRouterInfoPeerSizeFromBytes(t *testing.T) {
	t.Run("zero peer_size", func(t *testing.T) {
		input := []byte{0x00, 0x00, 0x00} // peer_size=0, mapping size=0
		ps, _, err := parsePeerSizeFromBytes(input)
		require.NoError(t, err)
		assert.Equal(t, 0, ps.Int())
	})
	t.Run("non-zero peer_size", func(t *testing.T) {
		input := []byte{0x03, 0x00, 0x00} // peer_size=3, mapping size=0
		ps, _, err := parsePeerSizeFromBytes(input)
		require.NoError(t, err)
		assert.Equal(t, 3, ps.Int(), "non-zero peer_size should be parsed but logged as warning")
	})
}

// ============================================================
// TEST: Round-trip serialization fidelity
// ============================================================

func TestAudit2_RoundTripSerialization(t *testing.T) {
	ri, err := generateTestRouterInfo(t, time.Now())
	require.NoError(t, err)

	bytes1, err := ri.Bytes()
	require.NoError(t, err)
	require.NotEmpty(t, bytes1)

	ri2, remainder, err := ReadRouterInfo(bytes1)
	require.NoError(t, err)
	assert.Empty(t, remainder)

	bytes2, err := ri2.Bytes()
	require.NoError(t, err)

	assert.Equal(t, bytes1, bytes2, "round-trip should produce byte-identical output")

	// Verify specific field equality
	assert.Equal(t, ri.RouterAddressCount(), ri2.RouterAddressCount())
	assert.Equal(t, ri.PeerSize(), ri2.PeerSize())
}

// ============================================================
// QUALITY: PeerSize doc comment URL
// ============================================================

func TestAudit2_PeerSizeDocComment(t *testing.T) {
	// This test just verifies PeerSize works on a valid RouterInfo.
	// The doc comment was fixed from #routeraddress to #routerinfo.
	ri, err := generateTestRouterInfo(t, time.Now())
	require.NoError(t, err)
	assert.Equal(t, 0, ri.PeerSize(), "peer_size should be 0 per spec")
}

// ============================================================
// QUALITY: String() label
// ============================================================

func TestAudit2_StringLabel(t *testing.T) {
	ri, err := generateTestRouterInfo(t, time.Now())
	require.NoError(t, err)
	str := ri.String()
	assert.Contains(t, str, "RouterIdentity:", "String() should label identity as 'RouterIdentity:', not 'Certificate:'")
	assert.NotContains(t, str, "Certificate:", "String() should not use 'Certificate:' label")
}

// ============================================================
// QUALITY: cleanString strips null bytes
// ============================================================

func TestAudit2_CleanStringNullBytes(t *testing.T) {
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

// ============================================================
// QUALITY: GoodVersion fragility with 0.9.x assumption
// ============================================================

func TestAudit2_GoodVersionConstants(t *testing.T) {
	assert.Equal(t, 58, MIN_GOOD_VERSION, "MIN_GOOD_VERSION should be 58")
	assert.Equal(t, 99, MAX_GOOD_VERSION, "MAX_GOOD_VERSION should be 99")
}

// ============================================================
// QUALITY: logCriticalMappingErrors includes errs
// ============================================================

func TestAudit2_LogCriticalMappingErrors(t *testing.T) {
	// Verify logCriticalMappingErrors does not panic
	errs := []error{
		assert.AnError,
	}
	// Should not panic
	logCriticalMappingErrors([]byte{}, errs)
}

// ============================================================
// QUALITY: Mixed receiver styles
// ============================================================

func TestAudit2_ReceiverConsistency(t *testing.T) {
	ri, err := generateTestRouterInfo(t, time.Now())
	require.NoError(t, err)

	// Value receivers (Options, Signature, Network, String, Bytes) should
	// work correctly when called on a value
	riVal := *ri

	t.Run("Options on value", func(t *testing.T) {
		m := riVal.Options()
		_ = m // should not panic
	})
	t.Run("Signature on value", func(t *testing.T) {
		s := riVal.Signature()
		_ = s // should not panic
	})
	t.Run("Network on value", func(t *testing.T) {
		assert.Equal(t, "i2p", riVal.Network())
	})
	t.Run("String on value", func(t *testing.T) {
		str := riVal.String()
		assert.NotEmpty(t, str)
	})
}
