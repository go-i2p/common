package router_address

import (
	"errors"
	"testing"
	"time"

	"github.com/go-i2p/common/data"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =========================================================================
// ReadRouterAddress Tests
// =========================================================================

func TestReadRouterAddressReturnsCorrectRemainderWithoutError(t *testing.T) {
	assert := assert.New(t)

	router_address_bytes := []byte{0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	str, _ := data.ToI2PString("foo")
	mapping, _ := data.GoMapToMapping(map[string]string{"host": "127.0.0.1", "port": "4567"})
	router_address_bytes = append(router_address_bytes, []byte(str)...)
	router_address_bytes = append(router_address_bytes, mapping.Data()...)
	router_address_bytes = append(router_address_bytes, []byte{0x01, 0x02, 0x03}...)
	router_address, remainder, err := ReadRouterAddress(router_address_bytes)

	assert.Nil(err, "ReadRouterAddress() reported error with valid data:")
	assert.Equal(0, len(remainder)-3)

	err, exit := router_address.checkValid()
	assert.Nil(err, "checkValid() on address from ReadRouterAddress() reported error with valid data")
	assert.Equal(exit, false, "checkValid() on address from ReadRouterAddress() indicated to stop parsing valid data")
}

func TestReadRouterAddressAcceptsZeroExpiration(t *testing.T) {
	ra, err := NewRouterAddress(5, time.Time{}, "NTCP2", map[string]string{"host": "127.0.0.1"})
	require.NoError(t, err)

	serialized := ra.Bytes()
	require.NotNil(t, serialized)

	parsed, _, err := ReadRouterAddress(serialized)
	assert.NoError(t, err, "ReadRouterAddress should succeed with zero expiration")
	assert.Equal(t, 5, parsed.Cost())
}

func TestReadRouterAddressNonZeroExpiration(t *testing.T) {
	t.Run("non-zero expiration returns ErrNonZeroExpiration with valid address", func(t *testing.T) {
		buf := []byte{0x05}
		buf = append(buf, 0x00, 0x00, 0x01, 0x8F, 0x5C, 0xE4, 0x00, 0x00)
		transportStr, _ := data.ToI2PString("NTCP2")
		buf = append(buf, transportStr...)
		mapping, _ := data.GoMapToMapping(map[string]string{})
		buf = append(buf, mapping.Data()...)

		ra, _, err := ReadRouterAddress(buf)
		// Non-zero expiration is a spec violation; ErrNonZeroExpiration is returned.
		assert.Error(t, err, "ReadRouterAddress should return ErrNonZeroExpiration for non-zero expiration")
		assert.True(t, errors.Is(err, ErrNonZeroExpiration), "error should be ErrNonZeroExpiration, got: %v", err)
		// The address itself is still populated.
		assert.Equal(t, 5, ra.Cost())
		exp := ra.Expiration()
		assert.False(t, isAllZeros(exp[:]), "Non-zero expiration should be preserved")
	})

	t.Run("zero expiration accepted with no error", func(t *testing.T) {
		buf := []byte{0x05}
		buf = append(buf, make([]byte, 8)...)
		transportStr, _ := data.ToI2PString("NTCP2")
		buf = append(buf, transportStr...)
		mapping, _ := data.GoMapToMapping(map[string]string{})
		buf = append(buf, mapping.Data()...)

		ra, _, err := ReadRouterAddress(buf)
		assert.NoError(t, err)
		exp := ra.Expiration()
		assert.True(t, isAllZeros(exp[:]), "Zero expiration should be all zeros")
	})
}

func TestReadRouterAddressExpirationWarning(t *testing.T) {
	buf := []byte{0x0A}
	buf = append(buf, 0x00, 0x00, 0x01, 0x8F, 0x5C, 0xE4, 0x00, 0x00)
	transportStr, _ := data.ToI2PString("NTCP2")
	buf = append(buf, transportStr...)
	mapping, _ := data.GoMapToMapping(map[string]string{})
	buf = append(buf, mapping.Data()...)

	ra, _, err := ReadRouterAddress(buf)
	assert.True(t, errors.Is(err, ErrNonZeroExpiration), "should return ErrNonZeroExpiration for non-zero expiration, got: %v", err)
	assert.Equal(t, 10, ra.Cost())

	exp := ra.Expiration()
	assert.False(t, isAllZeros(exp[:]))
}

func TestReadRouterAddressMalformedMapping(t *testing.T) {
	buf := []byte{0x05}
	buf = append(buf, make([]byte, 8)...)
	transportStr, _ := data.ToI2PString("NTCP2")
	buf = append(buf, transportStr...)
	buf = append(buf, 0x00, 0x0A)
	buf = append(buf, 0xFF, 0xFF)

	_, _, err := ReadRouterAddress(buf)
	_ = err
}

func TestReadRouterAddressEmptyMappingNoPanic(t *testing.T) {
	buf := []byte{0x05}
	buf = append(buf, make([]byte, 8)...)
	transportStr, _ := data.ToI2PString("X")
	buf = append(buf, transportStr...)
	buf = append(buf, 0x00, 0x00)

	ra, _, err := ReadRouterAddress(buf)
	assert.NoError(t, err, "ReadRouterAddress should parse minimal valid data")
	assert.Equal(t, 5, ra.Cost())
}

// =========================================================================
// Minimum size validation Tests
// =========================================================================

func TestValidateRouterAddressDataMinSize(t *testing.T) {
	t.Run("empty input", func(t *testing.T) {
		_, _, err := ReadRouterAddress([]byte{})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no data")
	})

	t.Run("1 byte input", func(t *testing.T) {
		_, _, err := ReadRouterAddress([]byte{0x01})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "data too small")
	})

	t.Run("11 bytes input (under minimum)", func(t *testing.T) {
		_, _, err := ReadRouterAddress(make([]byte, 11))
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "data too small")
	})

	t.Run("12 bytes input with valid transport (exact minimum)", func(t *testing.T) {
		// 1 (cost) + 8 (expiration) + 1 (transport length "X") + 1 ("X") + 2 (mapping size) = 13
		// With a single char transport, we need at least 13 bytes.
		// But 12 is the minimum with a 0-length transport string (now rejected).
		// Test that a minimal valid wire packet (with 1-char transport) works:
		buf := []byte{0x05}                      // cost
		buf = append(buf, make([]byte, 8)...)    // expiration
		transportStr, _ := data.ToI2PString("X") // 2 bytes: length + "X"
		buf = append(buf, transportStr...)
		buf = append(buf, 0x00, 0x00) // mapping size = 0

		_, _, err := ReadRouterAddress(buf)
		assert.NoError(t, err, "minimal valid data should be accepted")
	})
}

// =========================================================================
// Empty transport_style validation
// =========================================================================

func TestReadRouterAddress_EmptyTransportStyle(t *testing.T) {
	t.Run("zero-length transport_style rejected", func(t *testing.T) {
		wireData := make([]byte, 0, 20)
		wireData = append(wireData, 0x05)               // cost
		wireData = append(wireData, make([]byte, 8)...) // expiration (all zeros)
		wireData = append(wireData, 0x00)               // I2PString length byte = 0 (empty string)
		wireData = append(wireData, 0x00, 0x00)         // mapping size = 0

		_, _, err := ReadRouterAddress(wireData)
		assert.Error(t, err, "ReadRouterAddress should reject empty transport_style")
		assert.True(t, errors.Is(err, ErrEmptyTransportStyle), "error should be ErrEmptyTransportStyle, got: %v", err)
	})

	t.Run("non-empty transport_style accepted", func(t *testing.T) {
		ra, err := NewRouterAddress(5, time.Time{}, "NTCP2", map[string]string{})
		require.NoError(t, err)
		serialized := ra.Bytes()
		require.NotNil(t, serialized)

		parsed, _, err := ReadRouterAddress(serialized)
		assert.NoError(t, err)
		style, _ := parsed.TransportStyle().Data()
		assert.Equal(t, "NTCP2", style)
	})
}

// =========================================================================
// ReadRouterAddress sentinel errors
// =========================================================================

func TestReadRouterAddress_SentinelErrors(t *testing.T) {
	t.Run("ErrNoData from ReadRouterAddress", func(t *testing.T) {
		_, _, err := ReadRouterAddress([]byte{})
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrNoData), "Should be ErrNoData, got: %v", err)
	})

	t.Run("ErrDataTooSmall from ReadRouterAddress", func(t *testing.T) {
		_, _, err := ReadRouterAddress([]byte{0x05, 0x00, 0x00})
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrDataTooSmall), "Should be ErrDataTooSmall, got: %v", err)
	})
}
