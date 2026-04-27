package router_info

import (
	"testing"
	"time"

	"github.com/go-i2p/common/data"
	"github.com/go-i2p/common/router_address"
	"github.com/go-i2p/common/signature"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

//
// Validate method tests
//

func TestRouterInfoValidate(t *testing.T) {
	t.Run("valid router info passes", func(t *testing.T) {
		ri, err := generateTestRouterInfo(t, time.Now())
		require.NoError(t, err)
		assert.NoError(t, ri.Validate())
	})

	t.Run("nil router info", func(t *testing.T) {
		var ri *RouterInfo
		err := ri.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "router info is nil")
	})

	t.Run("nil identity", func(t *testing.T) {
		publishedDate, err := createPublishedDate(time.Now())
		require.NoError(t, err)
		sizeInt, peerSizeInt, err := createSizeIntegers([]*router_address.RouterAddress{{}})
		require.NoError(t, err)
		options, err := data.GoMapToMapping(map[string]string{})
		require.NoError(t, err)

		ri := &RouterInfo{
			router_identity: nil,
			published:       publishedDate,
			size:            sizeInt,
			addresses:       []*router_address.RouterAddress{{}},
			peer_size:       peerSizeInt,
			options:         options,
			signature:       &signature.Signature{},
		}
		err = ri.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "router identity is required")
	})

	t.Run("nil published date", func(t *testing.T) {
		keyPair := generateTestKeyPair(t)
		routerIdentity := assembleTestRouterIdentity(t, keyPair)
		sizeInt, peerSizeInt, err := createSizeIntegers([]*router_address.RouterAddress{{}})
		require.NoError(t, err)
		options, err := data.GoMapToMapping(map[string]string{})
		require.NoError(t, err)

		ri := &RouterInfo{
			router_identity: routerIdentity,
			published:       nil,
			size:            sizeInt,
			addresses:       []*router_address.RouterAddress{{}},
			peer_size:       peerSizeInt,
			options:         options,
			signature:       &signature.Signature{},
		}
		err = ri.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "published date is required")
	})

	t.Run("zero addresses is spec-valid", func(t *testing.T) {
		keyPair := generateTestKeyPair(t)
		routerIdentity := assembleTestRouterIdentity(t, keyPair)
		publishedDate, err := createPublishedDate(time.Now())
		require.NoError(t, err)
		sizeInt, peerSizeInt, err := createSizeIntegers([]*router_address.RouterAddress{})
		require.NoError(t, err)
		options, err := data.GoMapToMapping(map[string]string{"router.version": "0.9.64"})
		require.NoError(t, err)

		ri := &RouterInfo{
			router_identity: routerIdentity,
			published:       publishedDate,
			size:            sizeInt,
			addresses:       []*router_address.RouterAddress{},
			peer_size:       peerSizeInt,
			options:         options,
			signature:       &signature.Signature{},
		}
		err = ri.Validate()
		assert.NoError(t, err, "zero addresses should be spec-valid (size 0-255)")
	})

	t.Run("nil options", func(t *testing.T) {
		keyPair := generateTestKeyPair(t)
		routerIdentity := assembleTestRouterIdentity(t, keyPair)
		publishedDate, err := createPublishedDate(time.Now())
		require.NoError(t, err)
		sizeInt, peerSizeInt, err := createSizeIntegers([]*router_address.RouterAddress{{}})
		require.NoError(t, err)

		ri := &RouterInfo{
			router_identity: routerIdentity,
			published:       publishedDate,
			size:            sizeInt,
			addresses:       []*router_address.RouterAddress{{}},
			peer_size:       peerSizeInt,
			options:         nil,
			signature:       &signature.Signature{},
		}
		err = ri.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "options mapping is required")
	})

	t.Run("nil signature", func(t *testing.T) {
		keyPair := generateTestKeyPair(t)
		routerIdentity := assembleTestRouterIdentity(t, keyPair)
		publishedDate, err := createPublishedDate(time.Now())
		require.NoError(t, err)
		sizeInt, peerSizeInt, err := createSizeIntegers([]*router_address.RouterAddress{{}})
		require.NoError(t, err)
		options, err := data.GoMapToMapping(map[string]string{"test": "value"})
		require.NoError(t, err)

		ri := &RouterInfo{
			router_identity: routerIdentity,
			published:       publishedDate,
			size:            sizeInt,
			addresses:       []*router_address.RouterAddress{{}},
			peer_size:       peerSizeInt,
			options:         options,
			signature:       nil,
		}
		err = ri.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "signature is required")
	})
}

//
// IsValid convenience method
//

func TestRouterInfoIsValid(t *testing.T) {
	t.Run("valid returns true", func(t *testing.T) {
		ri, err := generateTestRouterInfo(t, time.Now())
		require.NoError(t, err)
		assert.True(t, ri.IsValid())
	})

	t.Run("nil returns false", func(t *testing.T) {
		var ri *RouterInfo
		assert.False(t, ri.IsValid())
	})

	t.Run("nil identity returns false", func(t *testing.T) {
		publishedDate, err := createPublishedDate(time.Now())
		require.NoError(t, err)
		sizeInt, peerSizeInt, err := createSizeIntegers([]*router_address.RouterAddress{{}})
		require.NoError(t, err)
		options, err := data.GoMapToMapping(map[string]string{})
		require.NoError(t, err)

		ri := &RouterInfo{
			router_identity: nil,
			published:       publishedDate,
			size:            sizeInt,
			addresses:       []*router_address.RouterAddress{{}},
			peer_size:       peerSizeInt,
			options:         options,
			signature:       &signature.Signature{},
		}
		assert.False(t, ri.IsValid())
	})
}

//
// Bytes() nil field error handling
//

func TestBytesPanicsOnNilFields(t *testing.T) {
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

//
// Zero-value accessor safety
//

func TestZeroValueRouterInfoAccessors(t *testing.T) {
	ri := &RouterInfo{}
	t.Run("RouterAddressCount", func(t *testing.T) {
		assert.Equal(t, 0, ri.RouterAddressCount())
	})
	t.Run("PeerSize", func(t *testing.T) {
		assert.Equal(t, 0, ri.PeerSize())
	})
	t.Run("Options", func(t *testing.T) {
		m := RouterInfo{}.Options()
		_ = m
	})
	t.Run("Signature", func(t *testing.T) {
		sig := RouterInfo{}.Signature()
		assert.Equal(t, 0, sig.Len())
	})
	t.Run("RouterAddresses", func(t *testing.T) {
		assert.Nil(t, ri.RouterAddresses())
	})
	t.Run("Published", func(t *testing.T) {
		assert.Nil(t, ri.Published())
	})
	t.Run("RouterIdentity", func(t *testing.T) {
		assert.Nil(t, ri.RouterIdentity())
	})
	t.Run("Bytes on zero value", func(t *testing.T) {
		_, err := RouterInfo{}.Bytes()
		assert.Error(t, err)
	})
	t.Run("String on zero value", func(t *testing.T) {
		str := RouterInfo{}.String()
		assert.NotEmpty(t, str)
	})
}

//
// VerifySignature nil field handling
//

func TestVerifySignatureNilFields(t *testing.T) {
	t.Run("zero-value router info", func(t *testing.T) {
		ri := &RouterInfo{}
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

//
// ReadRouterInfo malformed input
//

func TestReadRouterInfoMalformedInput(t *testing.T) {
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
		_, _, err := ReadRouterInfo(make([]byte, 100))
		assert.Error(t, err)
	})
	t.Run("exactly min size but invalid", func(t *testing.T) {
		fakeData := make([]byte, ROUTER_INFO_MIN_SIZE)
		_, _, _ = ReadRouterInfo(fakeData) // must not panic
	})
}

//
// parsePeerSizeFromBytes
//

func TestParsePeerSizeFromBytes(t *testing.T) {
	t.Run("zero peer_size", func(t *testing.T) {
		input := []byte{0x00, 0x00, 0x00}
		ps, _, err := parsePeerSizeFromBytes(input)
		require.NoError(t, err)
		assert.Equal(t, 0, ps.Int())
	})
	t.Run("non-zero peer_size skips hashes", func(t *testing.T) {
		// peer_size=3 means skip 3*32=96 bytes of peer hashes
		input := make([]byte, 1+96+2) // 1 byte peer_size + 96 hash bytes + 2 extra
		input[0] = 0x03               // peer_size = 3
		input[97] = 0xBB              // marker byte in remainder
		ps, remainder, err := parsePeerSizeFromBytes(input)
		require.NoError(t, err)
		assert.Equal(t, 3, ps.Int())
		assert.Equal(t, 2, len(remainder))
		assert.Equal(t, byte(0xBB), remainder[0])
	})
	t.Run("peer_size 5 skips 160 bytes", func(t *testing.T) {
		// peer_size=5 means skip 5*32=160 bytes of peer hashes
		input := make([]byte, 1+160+2)
		input[0] = 0x05 // peer_size = 5
		ps, remainder, err := parsePeerSizeFromBytes(input)
		require.NoError(t, err)
		assert.Equal(t, 5, ps.Int())
		assert.Equal(t, 2, len(remainder))
	})
}

//
// AddAddress overflow
//

func TestAddAddressOverflow255(t *testing.T) {
	ri, err := generateTestRouterInfo(t, time.Now())
	require.NoError(t, err)

	for i := len(ri.addresses); i < 255; i++ {
		opts := map[string]string{}
		addr, err := router_address.NewRouterAddress(byte(i%256), <-time.After(0), "SSU2", opts)
		require.NoError(t, err)
		err = ri.AddAddress(addr)
		require.NoError(t, err)
	}
	assert.Equal(t, 255, len(ri.addresses))
	assert.Equal(t, 255, ri.RouterAddressCount())

	opts := map[string]string{}
	addr, err := router_address.NewRouterAddress(1, <-time.After(0), "SSU2", opts)
	require.NoError(t, err)
	err = ri.AddAddress(addr)
	assert.Error(t, err)
	assert.Equal(t, 255, len(ri.addresses))
}

//
// logCriticalMappingErrors does not panic
//

func TestLogCriticalMappingErrors(t *testing.T) {
	errs := []error{assert.AnError}
	logCriticalMappingErrors([]byte{}, errs)
}

//
// NULL cert signature type
//

func TestParseRouterInfoSignatureNULLCert(t *testing.T) {
	err := validateSignatureType(signature.SIGNATURE_TYPE_DSA_SHA1, nil)
	assert.NoError(t, err)
}

//
// checkLegacySignatureType
//

func TestCheckLegacySignatureType(t *testing.T) {
	t.Run("DSA_SHA1 returns legacy unsupported error", func(t *testing.T) {
		err := checkLegacySignatureType(signature.SIGNATURE_TYPE_DSA_SHA1)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "legacy unsupported")
		assert.Contains(t, err.Error(), "DSA_SHA1")
	})
	t.Run("RSA_2048 returns legacy unsupported error", func(t *testing.T) {
		err := checkLegacySignatureType(signature.SIGNATURE_TYPE_RSA_SHA256_2048)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "legacy unsupported")
		assert.Contains(t, err.Error(), "RSA")
	})
	t.Run("RSA_3072 returns legacy unsupported error", func(t *testing.T) {
		err := checkLegacySignatureType(signature.SIGNATURE_TYPE_RSA_SHA384_3072)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "legacy unsupported")
	})
	t.Run("RSA_4096 returns legacy unsupported error", func(t *testing.T) {
		err := checkLegacySignatureType(signature.SIGNATURE_TYPE_RSA_SHA512_4096)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "legacy unsupported")
	})
	t.Run("Ed25519 returns nil", func(t *testing.T) {
		err := checkLegacySignatureType(signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519)
		assert.NoError(t, err)
	})
	t.Run("ECDSA_P256 returns nil", func(t *testing.T) {
		err := checkLegacySignatureType(signature.SIGNATURE_TYPE_ECDSA_SHA256_P256)
		assert.NoError(t, err)
	})
	t.Run("ECDSA_P384 returns nil", func(t *testing.T) {
		err := checkLegacySignatureType(signature.SIGNATURE_TYPE_ECDSA_SHA384_P384)
		assert.NoError(t, err)
	})
	t.Run("RedDSA returns nil", func(t *testing.T) {
		err := checkLegacySignatureType(signature.SIGNATURE_TYPE_REDDSA_SHA512_ED25519)
		assert.NoError(t, err)
	})
}

//
// validateMinorVersion error message correctness
//

func TestValidateMinorVersionErrorMessage(t *testing.T) {
	_, err := validateMinorVersion("8", 0, "0.8.64")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "position 1", "error message should reference position 1 for minor version")
	assert.NotContains(t, err.Error(), "position 0", "error message should NOT reference position 0 for minor version")
}

//
// createSignerFromPrivateKey legacy type errors
//

func TestCreateSignerFromPrivateKeyLegacyErrors(t *testing.T) {
	keyPair := generateTestKeyPair(t)
	t.Run("DSA_SHA1 returns legacy unsupported", func(t *testing.T) {
		_, err := createSignerFromPrivateKey(&keyPair.ed25519PrivKey, signature.SIGNATURE_TYPE_DSA_SHA1)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "legacy unsupported")
	})
	t.Run("RSA_2048 returns legacy unsupported", func(t *testing.T) {
		_, err := createSignerFromPrivateKey(&keyPair.ed25519PrivKey, signature.SIGNATURE_TYPE_RSA_SHA256_2048)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "legacy unsupported")
	})
}

//
// ReadRouterInfo minimum length validation
//

func TestReadRouterInfoMinLengthCheck(t *testing.T) {
	t.Run("rejects data shorter than ROUTER_INFO_MIN_SIZE", func(t *testing.T) {
		shortData := make([]byte, ROUTER_INFO_MIN_SIZE-1)
		_, _, err := ReadRouterInfo(shortData)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "data too short")
	})
	t.Run("accepts data at exactly ROUTER_INFO_MIN_SIZE", func(t *testing.T) {
		// This should NOT fail the length check. It may or may not fail deeper
		// in parsing, but the error should never be "data too short".
		data := make([]byte, ROUTER_INFO_MIN_SIZE)
		_, _, err := ReadRouterInfo(data)
		if err != nil {
			assert.NotContains(t, err.Error(), "data too short")
		}
	})
}

//
// parsePeerSizeFromBytes with peer hash skipping
//

func TestParsePeerSizeSkipsPeerHashes(t *testing.T) {
	t.Run("peer_size=2 skips 64 bytes of peer hashes", func(t *testing.T) {
		// Build input: peer_size=2, followed by 64 bytes of hash data, then a marker byte
		input := make([]byte, 1+64+1) // 1 byte peer_size + 64 bytes hashes + 1 byte marker
		input[0] = 0x02               // peer_size = 2
		input[65] = 0xAA              // marker byte after the hashes
		ps, remainder, err := parsePeerSizeFromBytes(input)
		require.NoError(t, err)
		assert.Equal(t, 2, ps.Int())
		require.Len(t, remainder, 1)
		assert.Equal(t, byte(0xAA), remainder[0], "should skip past peer hashes to marker")
	})
	t.Run("peer_size=1 with insufficient data returns error", func(t *testing.T) {
		input := []byte{0x01, 0x00, 0x00} // peer_size=1 but only 2 bytes left (need 32)
		_, _, err := parsePeerSizeFromBytes(input)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not enough data to skip")
	})
}

//
// AddAddress nil guard
//

func TestAddAddressRejectsNil(t *testing.T) {
	ri, err := generateTestRouterInfo(t, time.Now())
	require.NoError(t, err)
	originalCount := len(ri.addresses)

	err = ri.AddAddress(nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "nil address")
	assert.Equal(t, originalCount, len(ri.addresses), "nil address should not be appended")
}

//
// Validate with size mismatch
//

func TestValidateRejectsSizeMismatch(t *testing.T) {
	ri, err := generateTestRouterInfo(t, time.Now())
	require.NoError(t, err)
	// Force a mismatch: set size to 5 but leave 1 address
	badSize, err := data.NewIntegerFromInt(5, 1)
	require.NoError(t, err)
	ri.size = badSize
	err = ri.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "size mismatch")
}

func TestRouterInfoValidatePublishable(t *testing.T) {
	t.Run("valid router info passes publishable validation", func(t *testing.T) {
		ri, err := generateTestRouterInfo(t, time.Now())
		require.NoError(t, err)
		assert.NoError(t, ri.ValidatePublishable())
	})

	t.Run("rejects unroutable router address host", func(t *testing.T) {
		keyPair := generateTestKeyPair(t)
		routerIdentity := assembleTestRouterIdentity(t, keyPair)
		publishedDate, err := createPublishedDate(time.Now())
		require.NoError(t, err)
		addr, err := router_address.NewRouterAddress(3, time.Now().Add(time.Hour), "NTCP2", map[string]string{"host": "0.0.0.0", "port": "12345"})
		require.NoError(t, err)
		sizeInt, peerSizeInt, err := createSizeIntegers([]*router_address.RouterAddress{addr})
		require.NoError(t, err)
		options, err := data.GoMapToMapping(map[string]string{"router.version": "0.9.64"})
		require.NoError(t, err)

		ri := &RouterInfo{
			router_identity: routerIdentity,
			published:       publishedDate,
			size:            sizeInt,
			addresses:       []*router_address.RouterAddress{addr},
			peer_size:       peerSizeInt,
			options:         options,
			signature:       &signature.Signature{},
		}

		err = ri.ValidatePublishable()
		require.Error(t, err)
		assert.ErrorIs(t, err, router_address.ErrUnroutableHost)
		assert.Contains(t, err.Error(), "address 0 is not publishable")
	})
}
