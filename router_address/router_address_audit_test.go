// Package router_address — tests added during 2026-02-25 audit remediation.
package router_address

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/go-i2p/common/data"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =========================================================================
// [AUDIT] ErrNonZeroExpiration is returned and detectable via errors.Is
// =========================================================================

func TestErrNonZeroExpirationIsDetectable(t *testing.T) {
	// Build a RouterAddress with a non-zero expiration field.
	buf := []byte{0x07}                                               // cost = 7
	buf = append(buf, 0x00, 0x00, 0x01, 0x8F, 0x5C, 0xE4, 0x00, 0x00) // non-zero expiration
	ts, _ := data.ToI2PString("NTCP2")
	buf = append(buf, ts...)
	m, _ := data.GoMapToMapping(map[string]string{"host": "127.0.0.1", "port": "9150"})
	buf = append(buf, m.Data()...)

	ra, _, err := ReadRouterAddress(buf)

	// The address is still fully populated despite the spec violation.
	assert.True(t, errors.Is(err, ErrNonZeroExpiration),
		"ReadRouterAddress must return ErrNonZeroExpiration for non-zero expiration, got: %v", err)
	assert.Equal(t, 7, ra.Cost(), "cost must be parsed even when expiration is non-zero")
	ts2, _ := ra.TransportStyle().Data()
	assert.Equal(t, "NTCP2", ts2)

	// HasNonZeroExpiration should confirm the state.
	assert.True(t, ra.HasNonZeroExpiration())
}

func TestZeroExpirationNoError(t *testing.T) {
	ra, err := NewRouterAddress(5, time.Time{}, "NTCP2", map[string]string{"host": "127.0.0.1"})
	require.NoError(t, err)
	serialized := ra.Bytes()
	require.NotNil(t, serialized)

	_, _, err2 := ReadRouterAddress(serialized)
	assert.NoError(t, err2, "zero expiration must produce no error")
}

// =========================================================================
// [AUDIT] Round-trip options equality
// =========================================================================

func TestRoundTripOptionsEquality(t *testing.T) {
	options := map[string]string{
		"host": "10.0.0.1",
		"port": "9150",
		"v":    "2",
	}
	original, err := NewRouterAddress(5, time.Time{}, "NTCP2", options)
	require.NoError(t, err)

	serialized := original.Bytes()
	require.NotNil(t, serialized)

	parsed, _, err := ReadRouterAddress(serialized)
	require.NoError(t, err)

	origOpts := original.Options()
	parsedOpts := parsed.Options()
	origBytes := (&origOpts).Data()
	parsedBytes := (&parsedOpts).Data()
	assert.True(t, bytes.Equal(origBytes, parsedBytes),
		"Mapping bytes must be identical after round-trip: orig=%x parsed=%x", origBytes, parsedBytes)

	for _, key := range []string{"host", "port", "v"} {
		k, _ := data.ToI2PString(key)
		origVal := original.GetOption(k)
		parsedVal := parsed.GetOption(k)
		require.NotNil(t, origVal, "original option %q must exist", key)
		require.NotNil(t, parsedVal, "parsed option %q must exist", key)
		origData, _ := origVal.Data()
		parsedData, _ := parsedVal.Data()
		assert.Equal(t, origData, parsedData, "option %q must survive round-trip", key)
	}
}

// =========================================================================
// [AUDIT] Network() with zero-length but non-nil TransportType
// =========================================================================

func TestNetworkEmptyNonNilTransportType(t *testing.T) {
	// Validated structs always have non-empty TransportType, but an unvalidated
	// struct constructed directly may have a non-nil zero-length slice.
	ra := &RouterAddress{
		TransportType: data.I2PString{}, // non-nil, zero-length
	}
	// Network() must not panic and must return "".
	assert.NotPanics(t, func() {
		result := ra.Network()
		assert.Equal(t, "", result,
			"Network() should return empty string for zero-length TransportType")
	})
}

// =========================================================================
// [AUDIT] Serialize() returns explicit error on invalid RouterAddress
// =========================================================================

func TestSerializeReturnsErrorOnInvalidAddress(t *testing.T) {
	t.Run("nil TransportCost", func(t *testing.T) {
		expDate, _, _ := data.NewDate(make([]byte, data.DATE_SIZE))
		m, _ := data.GoMapToMapping(map[string]string{})
		ts, _ := data.ToI2PString("NTCP2")
		ra := RouterAddress{
			TransportCost:    nil,
			ExpirationDate:   expDate,
			TransportType:    ts,
			TransportOptions: m,
		}
		b, err := ra.Serialize()
		assert.Nil(t, b)
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrMissingTransportCost))
	})

	t.Run("nil ExpirationDate", func(t *testing.T) {
		cost, _ := data.NewIntegerFromInt(5, 1)
		m, _ := data.GoMapToMapping(map[string]string{})
		ts, _ := data.ToI2PString("NTCP2")
		ra := RouterAddress{
			TransportCost:    cost,
			ExpirationDate:   nil,
			TransportType:    ts,
			TransportOptions: m,
		}
		b, err := ra.Serialize()
		assert.Nil(t, b)
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrMissingExpirationDate))
	})

	t.Run("nil TransportType", func(t *testing.T) {
		cost, _ := data.NewIntegerFromInt(5, 1)
		expDate, _, _ := data.NewDate(make([]byte, data.DATE_SIZE))
		m, _ := data.GoMapToMapping(map[string]string{})
		ra := RouterAddress{
			TransportCost:    cost,
			ExpirationDate:   expDate,
			TransportType:    nil,
			TransportOptions: m,
		}
		b, err := ra.Serialize()
		assert.Nil(t, b)
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrMissingTransportType))
	})

	t.Run("nil TransportOptions", func(t *testing.T) {
		cost, _ := data.NewIntegerFromInt(5, 1)
		expDate, _, _ := data.NewDate(make([]byte, data.DATE_SIZE))
		ts, _ := data.ToI2PString("NTCP2")
		ra := RouterAddress{
			TransportCost:    cost,
			ExpirationDate:   expDate,
			TransportType:    ts,
			TransportOptions: nil,
		}
		b, err := ra.Serialize()
		assert.Nil(t, b)
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrMissingTransportOptions))
	})

	t.Run("valid address serializes without error", func(t *testing.T) {
		ra, err := NewRouterAddress(5, time.Time{}, "NTCP2", map[string]string{"host": "127.0.0.1"})
		require.NoError(t, err)
		b, err := ra.Serialize()
		assert.NoError(t, err)
		assert.NotNil(t, b)
		assert.Greater(t, len(b), 0)
	})
}

// =========================================================================
// [AUDIT] Host() accepts hostnames per I2P spec
// =========================================================================

func TestHostAcceptsI2PHostnames(t *testing.T) {
	hostnames := []string{
		"router.example.i2p",
		"example.i2p",
		"test-router.net",
		"subdomain.router.i2p",
		"host123",
	}
	for _, hn := range hostnames {
		hn := hn
		t.Run(hn, func(t *testing.T) {
			ra, err := NewRouterAddress(5, time.Time{}, "NTCP2", map[string]string{"host": hn})
			require.NoError(t, err)
			addr, err := ra.Host()
			assert.NoError(t, err, "Host() should accept hostname %q per I2P spec", hn)
			assert.Equal(t, hn, addr.String())
			assert.Equal(t, "host", addr.Network())
			// HasValidHost should also return true for valid hostnames.
			assert.True(t, ra.HasValidHost(), "HasValidHost() should return true for hostname %q", hn)
		})
	}
}

// =========================================================================
// [AUDIT] ROUTER_ADDRESS_MIN_SIZE comment verification
// =========================================================================

// TestMinSizeIsPreParseGate ensures ROUTER_ADDRESS_MIN_SIZE (12) is a fast
// rejection threshold, not a guarantee of parseability.
func TestMinSizeIsPreParseGate(t *testing.T) {
	// 12-byte input with a zero-length transport style (0x00) passes the
	// ROUTER_ADDRESS_MIN_SIZE gate but fails parseTransportType.
	wireData := make([]byte, 0, 12)
	wireData = append(wireData, 0x05)               // cost
	wireData = append(wireData, make([]byte, 8)...) // expiration
	wireData = append(wireData, 0x00)               // I2PString len = 0 (empty transport)
	wireData = append(wireData, 0x00, 0x00)         // mapping size = 0

	_, _, err := ReadRouterAddress(wireData)
	assert.Error(t, err, "12-byte input with empty transport style must be rejected")
	assert.True(t, errors.Is(err, ErrEmptyTransportStyle),
		"error must be ErrEmptyTransportStyle, got: %v", err)
}
