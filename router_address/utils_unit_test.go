package router_address

import (
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
	t.Run("non-zero expiration parsed with warning but not rejected", func(t *testing.T) {
		buf := []byte{0x05}
		buf = append(buf, 0x00, 0x00, 0x01, 0x8F, 0x5C, 0xE4, 0x00, 0x00)
		buf = append(buf, 0x00)
		buf = append(buf, 0x00, 0x00)

		ra, _, err := ReadRouterAddress(buf)
		assert.NoError(t, err, "ReadRouterAddress should accept non-zero expiration with warning")
		assert.Equal(t, 5, ra.Cost())
		exp := ra.Expiration()
		assert.False(t, isAllZeros(exp[:]), "Non-zero expiration should be preserved")
	})

	t.Run("zero expiration accepted cleanly", func(t *testing.T) {
		buf := []byte{0x05}
		buf = append(buf, make([]byte, 8)...)
		buf = append(buf, 0x00)
		buf = append(buf, 0x00, 0x00)

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
	assert.NoError(t, err)
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
	buf = append(buf, 0x00)
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
		assert.Contains(t, err.Error(), "not enough data")
	})

	t.Run("11 bytes input (under minimum)", func(t *testing.T) {
		_, _, err := ReadRouterAddress(make([]byte, 11))
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not enough data")
	})

	t.Run("12 bytes input (exact minimum)", func(t *testing.T) {
		buf := make([]byte, 12)
		_, _, err := ReadRouterAddress(buf)
		assert.NoError(t, err, "12 bytes should be accepted as minimum valid")
	})
}
