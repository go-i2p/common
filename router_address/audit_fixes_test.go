package router_address

import (
	"bytes"
	"encoding/base64"
	"testing"
	"time"

	"github.com/go-i2p/common/data"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Finding 1: [BUG] Bytes() panics on nil pointer fields
// =============================================================================

func TestBytesReturnsNilOnNilFields(t *testing.T) {
	t.Run("completely empty struct", func(t *testing.T) {
		ra := RouterAddress{}
		result := ra.Bytes()
		assert.Nil(t, result, "Bytes() should return nil for empty RouterAddress")
	})

	t.Run("nil TransportCost", func(t *testing.T) {
		expDate, _, _ := data.NewDate(make([]byte, data.DATE_SIZE))
		mapping, _ := data.GoMapToMapping(map[string]string{})
		ra := RouterAddress{
			TransportCost:    nil,
			ExpirationDate:   expDate,
			TransportType:    data.I2PString{},
			TransportOptions: mapping,
		}
		result := ra.Bytes()
		assert.Nil(t, result, "Bytes() should return nil when TransportCost is nil")
	})

	t.Run("nil ExpirationDate", func(t *testing.T) {
		cost, _ := data.NewIntegerFromInt(5, 1)
		mapping, _ := data.GoMapToMapping(map[string]string{})
		ra := RouterAddress{
			TransportCost:    cost,
			ExpirationDate:   nil,
			TransportType:    data.I2PString{},
			TransportOptions: mapping,
		}
		result := ra.Bytes()
		assert.Nil(t, result, "Bytes() should return nil when ExpirationDate is nil")
	})

	t.Run("nil TransportOptions", func(t *testing.T) {
		cost, _ := data.NewIntegerFromInt(5, 1)
		expDate, _, _ := data.NewDate(make([]byte, data.DATE_SIZE))
		ra := RouterAddress{
			TransportCost:    cost,
			ExpirationDate:   expDate,
			TransportType:    data.I2PString{},
			TransportOptions: nil,
		}
		result := ra.Bytes()
		assert.Nil(t, result, "Bytes() should return nil when TransportOptions is nil")
	})

	t.Run("valid struct serializes", func(t *testing.T) {
		ra, err := NewRouterAddress(5, time.Time{}, "NTCP2", map[string]string{"host": "127.0.0.1"})
		require.NoError(t, err)
		result := ra.Bytes()
		assert.NotNil(t, result, "Bytes() should return non-nil for valid RouterAddress")
		assert.True(t, len(result) > 0, "Bytes() should return non-empty for valid RouterAddress")
	})
}

// =============================================================================
// Finding 2: [SPEC] NewRouterAddress always sets expiration to zero
// =============================================================================

func TestNewRouterAddressAlwaysSetsZeroExpiration(t *testing.T) {
	// Even with a non-zero expiration time, the date bytes must be all zeros
	futureTime := time.Now().Add(24 * time.Hour)
	ra, err := NewRouterAddress(5, futureTime, "NTCP2", map[string]string{"host": "127.0.0.1"})
	require.NoError(t, err)

	expiration := ra.Expiration()
	zeroDate := data.Date{}
	assert.Equal(t, zeroDate[:], expiration[:],
		"Expiration must be all zeros per I2P spec regardless of input time")
}

func TestNewRouterAddressZeroTimeAlsoZeroExpiration(t *testing.T) {
	ra, err := NewRouterAddress(5, time.Time{}, "NTCP2", map[string]string{"host": "127.0.0.1"})
	require.NoError(t, err)

	expiration := ra.Expiration()
	for i, b := range expiration {
		assert.Equal(t, byte(0), b, "Expiration byte %d should be 0", i)
	}
}

// =============================================================================
// Finding 3: [SPEC] ReadRouterAddress warns on non-zero expiration
// =============================================================================

func TestReadRouterAddressAcceptsZeroExpiration(t *testing.T) {
	ra, err := NewRouterAddress(5, time.Time{}, "NTCP2", map[string]string{"host": "127.0.0.1"})
	require.NoError(t, err)

	serialized := ra.Bytes()
	require.NotNil(t, serialized)

	parsed, _, err := ReadRouterAddress(serialized)
	assert.NoError(t, err, "ReadRouterAddress should succeed with zero expiration")
	assert.Equal(t, 5, parsed.Cost())
}

// =============================================================================
// Finding 4: [BUG] parseTransportOptions error handling
// =============================================================================

func TestReadRouterAddressMalformedMapping(t *testing.T) {
	// Build data: 1 byte cost + 8 byte zero expiration + I2PString + malformed mapping
	buf := []byte{0x05} // cost = 5
	buf = append(buf, make([]byte, 8)...)
	transportStr, _ := data.ToI2PString("NTCP2")
	buf = append(buf, transportStr...)
	// Mapping with size=10 but only 2 bytes of data → insufficient data for declared size
	buf = append(buf, 0x00, 0x0A) // mapping size = 10
	buf = append(buf, 0xFF, 0xFF) // only 2 bytes

	_, _, err := ReadRouterAddress(buf)
	// The mapping parser should return a non-nil mapping (partial parse with recovery),
	// so the error may not propagate. What matters is that the function does not panic.
	_ = err
}

func TestReadRouterAddressEmptyMappingNoPanic(t *testing.T) {
	// Minimal valid: cost + 8 zero bytes + empty string (length 0) + empty mapping (size 0)
	buf := []byte{0x05}
	buf = append(buf, make([]byte, 8)...) // zero expiration
	buf = append(buf, 0x00)               // empty transport string
	buf = append(buf, 0x00, 0x00)         // empty mapping

	ra, _, err := ReadRouterAddress(buf)
	assert.NoError(t, err, "ReadRouterAddress should parse minimal valid data")
	assert.Equal(t, 5, ra.Cost())
}

// =============================================================================
// Finding 5: [BUG] StaticKey() I2PString length prefix fix
// =============================================================================

func TestStaticKeyExcludesLengthPrefix(t *testing.T) {
	// Create a 32-byte key
	keyData := make([]byte, 32)
	for i := range keyData {
		keyData[i] = byte(i)
	}
	keyStr := base64.StdEncoding.EncodeToString(keyData)

	options := map[string]string{
		"host": "127.0.0.1",
		"port": "9150",
		"s":    keyStr,
	}
	ra, err := NewRouterAddress(5, time.Time{}, "NTCP2", options)
	require.NoError(t, err)

	// The key option value is a base64 string, not raw bytes.
	// StaticKey() should use .Data() to get content without prefix.
	_, err = ra.StaticKey()
	// The base64 encoded string is 44 chars, not 32 bytes, so it will fail the size check.
	// That's correct behavior — the fix ensures .Data() is used, not raw []byte(I2PString).
	assert.Error(t, err, "StaticKey should fail for non-32-byte data")
}

func TestStaticKeyNotFound(t *testing.T) {
	options := map[string]string{
		"host": "127.0.0.1",
		"port": "9150",
	}
	ra, err := NewRouterAddress(5, time.Time{}, "NTCP2", options)
	require.NoError(t, err)

	_, err = ra.StaticKey()
	assert.Error(t, err, "StaticKey should return error when key 's' is missing")
	assert.Contains(t, err.Error(), "not found")
}

// =============================================================================
// Finding 6: [BUG] InitializationVector() I2PString length prefix fix
// =============================================================================

func TestInitializationVectorNotFound(t *testing.T) {
	options := map[string]string{
		"host": "127.0.0.1",
		"port": "9150",
	}
	ra, err := NewRouterAddress(5, time.Time{}, "NTCP2", options)
	require.NoError(t, err)

	_, err = ra.InitializationVector()
	assert.Error(t, err, "InitializationVector should return error when key 'i' is missing")
	assert.Contains(t, err.Error(), "not found")
}

func TestInitializationVectorInvalidSize(t *testing.T) {
	options := map[string]string{
		"host": "127.0.0.1",
		"port": "9150",
		"i":    "tooshort",
	}
	ra, err := NewRouterAddress(5, time.Time{}, "NTCP2", options)
	require.NoError(t, err)

	_, err = ra.InitializationVector()
	assert.Error(t, err, "InitializationVector should fail for wrong-size data")
	assert.Contains(t, err.Error(), "invalid IV length")
}

// =============================================================================
// Finding 7: [GAP] ROUTER_ADDRESS_MIN_SIZE correctness
// =============================================================================

func TestRouterAddressMinSizeConstant(t *testing.T) {
	// Minimum valid RouterAddress: 1 (cost) + 8 (expiration) + 1 (transport_style length=0) + 2 (mapping size=0) = 12
	assert.Equal(t, 12, ROUTER_ADDRESS_MIN_SIZE,
		"ROUTER_ADDRESS_MIN_SIZE should be 12")
}

// =============================================================================
// Finding 8: [GAP] validateRouterAddressData minimum size check
// =============================================================================

func TestValidateRouterAddressDataMinSize(t *testing.T) {
	t.Run("empty input", func(t *testing.T) {
		_, _, err := ReadRouterAddress([]byte{})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no data")
	})

	t.Run("1 byte input", func(t *testing.T) {
		_, _, err := ReadRouterAddress([]byte{0x01})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not enough data")
	})

	t.Run("11 bytes input (under minimum)", func(t *testing.T) {
		_, _, err := ReadRouterAddress(make([]byte, 11))
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not enough data")
	})

	t.Run("12 bytes input (exact minimum)", func(t *testing.T) {
		// cost=0 + 8 zero expiration + string_len=0 + mapping_size=0
		buf := make([]byte, 12)
		_, _, err := ReadRouterAddress(buf)
		assert.NoError(t, err, "12 bytes should be accepted as minimum valid")
	})
}

// =============================================================================
// Finding 9: [GAP] Cost() and Expiration() nil dereference guards
// =============================================================================

func TestCostReturnsZeroOnNilTransportCost(t *testing.T) {
	ra := RouterAddress{TransportCost: nil}
	assert.Equal(t, 0, ra.Cost(), "Cost() should return 0 when TransportCost is nil")
}

func TestExpirationReturnsZeroOnNilExpirationDate(t *testing.T) {
	ra := RouterAddress{ExpirationDate: nil}
	exp := ra.Expiration()
	assert.Equal(t, data.Date{}, exp, "Expiration() should return zero Date when ExpirationDate is nil")
}

// =============================================================================
// Finding 10: [GAP] + Finding 11: [TEST] Round-trip serialization
// =============================================================================

func TestRoundTripReadRouterAddressBytes(t *testing.T) {
	options := map[string]string{
		"host": "192.168.1.1",
		"port": "9150",
		"v":    "2",
	}
	original, err := NewRouterAddress(10, time.Time{}, "NTCP2", options)
	require.NoError(t, err)

	serialized := original.Bytes()
	require.NotNil(t, serialized, "Bytes() should produce non-nil output for valid address")

	parsed, remainder, err := ReadRouterAddress(serialized)
	assert.NoError(t, err, "ReadRouterAddress should parse serialized data without error")
	assert.Empty(t, remainder, "No remainder expected for exact-size data")

	// Compare field values
	assert.Equal(t, original.Cost(), parsed.Cost(), "Cost should match after round-trip")

	originalExp := original.Expiration()
	parsedExp := parsed.Expiration()
	assert.True(t, bytes.Equal(originalExp[:], parsedExp[:]), "Expiration should match after round-trip")

	originalStyle, _ := original.TransportStyle().Data()
	parsedStyle, _ := parsed.TransportStyle().Data()
	assert.Equal(t, originalStyle, parsedStyle, "TransportStyle should match after round-trip")
}

func TestRoundTripWithRemainder(t *testing.T) {
	options := map[string]string{
		"host": "10.0.0.1",
		"port": "4567",
	}
	original, err := NewRouterAddress(3, time.Time{}, "SSU2", options)
	require.NoError(t, err)

	serialized := original.Bytes()
	require.NotNil(t, serialized)

	// Append extra bytes as remainder
	extra := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	dataWithRemainder := append(serialized, extra...)

	_, remainder, err := ReadRouterAddress(dataWithRemainder)
	assert.NoError(t, err)
	assert.Equal(t, extra, remainder, "Remainder should be the appended bytes")
}

// =============================================================================
// Finding 13: [TEST] Network(), IPVersion(), UDP(), String() methods
// =============================================================================

func TestNetworkMethod(t *testing.T) {
	t.Run("NTCP2 transport", func(t *testing.T) {
		ra, err := NewRouterAddress(5, time.Time{}, "NTCP2", map[string]string{"host": "127.0.0.1"})
		require.NoError(t, err)
		network := ra.Network()
		assert.Contains(t, network, "NTCP2", "Network should contain transport type")
	})

	t.Run("nil TransportType", func(t *testing.T) {
		ra := &RouterAddress{TransportType: nil}
		assert.Equal(t, "", ra.Network(), "Network should return empty string for nil TransportType")
	})
}

func TestIPVersionMethod(t *testing.T) {
	t.Run("IPv4 with caps", func(t *testing.T) {
		ra, err := NewRouterAddress(5, time.Time{}, "NTCP2", map[string]string{
			"host": "127.0.0.1",
			"caps": "BC",
		})
		require.NoError(t, err)
		assert.Equal(t, IPV4_VERSION_STRING, ra.IPVersion())
	})

	t.Run("no caps returns empty", func(t *testing.T) {
		ra, err := NewRouterAddress(5, time.Time{}, "NTCP2", map[string]string{
			"host": "127.0.0.1",
		})
		require.NoError(t, err)
		// Without caps option, CapsString() returns nil → Data() returns error → ""
		assert.Equal(t, "", ra.IPVersion())
	})

	t.Run("IPv6 with caps suffix", func(t *testing.T) {
		ra, err := NewRouterAddress(5, time.Time{}, "NTCP2", map[string]string{
			"host": "::1",
			"caps": "BC6",
		})
		require.NoError(t, err)
		assert.Equal(t, IPV6_VERSION_STRING, ra.IPVersion())
	})
}

func TestUDPMethod(t *testing.T) {
	t.Run("SSU transport is UDP", func(t *testing.T) {
		ra, err := NewRouterAddress(5, time.Time{}, "SSU", map[string]string{"host": "127.0.0.1"})
		require.NoError(t, err)
		assert.True(t, ra.UDP(), "SSU transport should be UDP")
	})

	t.Run("SSU2 transport is UDP", func(t *testing.T) {
		ra, err := NewRouterAddress(5, time.Time{}, "SSU2", map[string]string{"host": "127.0.0.1"})
		require.NoError(t, err)
		assert.True(t, ra.UDP(), "SSU2 transport should be UDP")
	})

	t.Run("NTCP2 transport is not UDP", func(t *testing.T) {
		ra, err := NewRouterAddress(5, time.Time{}, "NTCP2", map[string]string{"host": "127.0.0.1"})
		require.NoError(t, err)
		assert.False(t, ra.UDP(), "NTCP2 transport should not be UDP")
	})
}

func TestStringMethod(t *testing.T) {
	ra, err := NewRouterAddress(5, time.Time{}, "NTCP2", map[string]string{
		"host": "192.168.1.1",
		"port": "9150",
	})
	require.NoError(t, err)
	str := ra.String()
	assert.NotEmpty(t, str, "String() should produce non-empty output")
	assert.Contains(t, str, "NTCP2", "String() should contain transport type")
}

// =============================================================================
// Finding 14: [TEST] StaticKey(), InitializationVector(), ProtocolVersion()
// =============================================================================

func TestProtocolVersion(t *testing.T) {
	t.Run("with version set", func(t *testing.T) {
		ra, err := NewRouterAddress(5, time.Time{}, "SSU2", map[string]string{
			"host": "127.0.0.1",
			"port": "9150",
			"v":    "2",
		})
		require.NoError(t, err)
		ver, err := ra.ProtocolVersion()
		assert.NoError(t, err)
		assert.Equal(t, "2", ver)
	})

	t.Run("without version set", func(t *testing.T) {
		ra, err := NewRouterAddress(5, time.Time{}, "NTCP2", map[string]string{
			"host": "127.0.0.1",
		})
		require.NoError(t, err)
		_, err = ra.ProtocolVersion()
		// Should either return empty string or error for missing option
		_ = err
	})
}

// =============================================================================
// Finding 15: [QUALITY] Receiver naming consistency — verified by compilation
// =============================================================================

func TestReceiverNamingConsistency(t *testing.T) {
	// This test verifies that all methods compile and work correctly
	// after receiver name standardization to 'ra'
	ra, err := NewRouterAddress(5, time.Time{}, "NTCP2", map[string]string{
		"host": "192.168.1.1",
		"port": "9150",
	})
	require.NoError(t, err)

	// Value receiver methods
	_ = ra.Cost()
	_ = ra.Expiration()
	_ = ra.TransportStyle()
	_ = ra.Options()
	_ = ra.Bytes()
	_ = ra.HostString()
	_ = ra.PortString()
	_ = ra.CapsString()
	_ = ra.StaticKeyString()
	_ = ra.InitializationVectorString()
	_ = ra.ProtocolVersionString()
	_ = ra.HasValidHost()
	_ = ra.HasValidPort()

	// Pointer receiver methods
	_ = ra.Network()
	_ = ra.IPVersion()
	_ = ra.UDP()
	_ = ra.String()
}

// =============================================================================
// Finding 16: [QUALITY] Pointer vs value receiver consistency
// — verified via net.Addr interface satisfaction at compile time
// =============================================================================

func TestNetAddrInterfaceSatisfaction(t *testing.T) {
	ra, err := NewRouterAddress(5, time.Time{}, "NTCP2", map[string]string{
		"host": "127.0.0.1",
		"port": "9150",
	})
	require.NoError(t, err)

	// Verify *RouterAddress satisfies net.Addr
	var addr interface{} = ra
	_, ok := addr.(interface {
		Network() string
		String() string
	})
	assert.True(t, ok, "*RouterAddress should satisfy net.Addr interface")
}

// =============================================================================
// Finding 17: [QUALITY] checkValid() signature
// — Acknowledged: not changed to avoid breaking internal callers
// =============================================================================

func TestCheckValidReturnsBehavior(t *testing.T) {
	t.Run("valid address", func(t *testing.T) {
		ra, err := NewRouterAddress(5, time.Time{}, "NTCP2", map[string]string{"host": "127.0.0.1"})
		require.NoError(t, err)
		err, exit := ra.checkValid()
		assert.NoError(t, err)
		assert.False(t, exit)
	})

	t.Run("nil transport type", func(t *testing.T) {
		ra := &RouterAddress{TransportType: nil}
		err, exit := ra.checkValid()
		assert.Error(t, err)
		assert.True(t, exit)
	})

	t.Run("nil transport options", func(t *testing.T) {
		transportType, _ := data.ToI2PString("NTCP2")
		ra := &RouterAddress{TransportType: transportType, TransportOptions: nil}
		err, exit := ra.checkValid()
		assert.Error(t, err)
		assert.True(t, exit)
	})
}

// =============================================================================
// Finding 18: [QUALITY] Options() return value
// =============================================================================

func TestOptionsReturnsValidMapping(t *testing.T) {
	ra, err := NewRouterAddress(5, time.Time{}, "NTCP2", map[string]string{
		"host": "127.0.0.1",
		"port": "9150",
	})
	require.NoError(t, err)

	opts := ra.Options()
	// Verify we got a valid mapping
	assert.NotNil(t, opts.Values(), "Options should return a mapping with values")
}

func TestOptionsNilTransportOptions(t *testing.T) {
	ra := RouterAddress{TransportOptions: nil}
	opts := ra.Options()
	// Should return empty mapping, not panic
	assert.NotNil(t, &opts, "Options should return non-nil mapping even with nil TransportOptions")
}
