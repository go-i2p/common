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
// NewRouterAddress Constructor Tests
// =========================================================================

func TestNewRouterAddressValid(t *testing.T) {
	assert := assert.New(t)

	options := map[string]string{
		"host": "192.168.1.1",
		"port": "9150",
	}
	expiration := time.Now().Add(24 * time.Hour)

	ra, err := NewRouterAddress(5, expiration, "NTCP2", options)

	assert.NoError(err, "NewRouterAddress should not return error with valid inputs")
	assert.NotNil(ra, "RouterAddress should not be nil")
	assert.Equal(5, ra.Cost(), "Cost should match input")
	assert.NoError(ra.Validate(), "Valid RouterAddress should pass validation")
	assert.True(ra.IsValid(), "IsValid should return true for valid RouterAddress")
}

func TestNewRouterAddressEmptyTransportType(t *testing.T) {
	assert := assert.New(t)

	options := map[string]string{"host": "192.168.1.1"}
	expiration := time.Now().Add(24 * time.Hour)

	ra, err := NewRouterAddress(5, expiration, "", options)

	assert.Error(err, "NewRouterAddress should return error with empty transport type")
	assert.Nil(ra, "RouterAddress should be nil on error")
	assert.Contains(err.Error(), "transport type cannot be empty")
}

func TestNewRouterAddressNilOptions(t *testing.T) {
	assert := assert.New(t)

	expiration := time.Now().Add(24 * time.Hour)

	ra, err := NewRouterAddress(5, expiration, "NTCP2", nil)

	assert.NoError(err, "NewRouterAddress should handle nil options")
	assert.NotNil(ra, "RouterAddress should not be nil")
}

func TestNewRouterAddressEmptyOptions(t *testing.T) {
	assert := assert.New(t)

	options := map[string]string{}
	expiration := time.Now().Add(24 * time.Hour)

	ra, err := NewRouterAddress(5, expiration, "NTCP2", options)

	assert.NoError(err, "NewRouterAddress should work with empty options")
	assert.NotNil(ra, "RouterAddress should not be nil")
}

func TestNewRouterAddressAlwaysSetsZeroExpiration(t *testing.T) {
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

func TestCreateExpirationDateIgnoresParameter(t *testing.T) {
	farFuture := time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)
	ra, err := NewRouterAddress(5, farFuture, "NTCP2", map[string]string{"host": "127.0.0.1"})
	require.NoError(t, err)

	exp := ra.Expiration()
	assert.True(t, isAllZeros(exp[:]), "Expiration must be all zeros regardless of input time")
}

// =========================================================================
// Validate Tests
// =========================================================================

func TestRouterAddressValidate(t *testing.T) {
	t.Run("valid router address passes validation", func(t *testing.T) {
		assert := assert.New(t)

		options := map[string]string{"host": "127.0.0.1", "port": "4567"}
		ra, err := NewRouterAddress(3, time.Now().Add(1*time.Hour), "SSU", options)
		assert.NoError(err)

		err = ra.Validate()
		assert.NoError(err, "Valid RouterAddress should pass validation")
	})

	t.Run("nil router address fails validation", func(t *testing.T) {
		assert := assert.New(t)

		var ra *RouterAddress
		err := ra.Validate()
		assert.Error(err, "Nil RouterAddress should fail validation")
		assert.Contains(err.Error(), "router address is nil")
	})

	t.Run("router address with nil transport cost fails validation", func(t *testing.T) {
		assert := assert.New(t)

		options, _ := data.GoMapToMapping(map[string]string{"host": "127.0.0.1"})
		transportType, _ := data.ToI2PString("SSU")
		expirationDate, _, _ := data.NewDate(make([]byte, data.DATE_SIZE))

		ra := &RouterAddress{
			TransportCost:    nil,
			ExpirationDate:   expirationDate,
			TransportType:    transportType,
			TransportOptions: options,
		}

		err := ra.Validate()
		assert.Error(err, "RouterAddress with nil cost should fail validation")
		assert.Contains(err.Error(), "transport cost is required")
	})

	t.Run("router address with nil expiration date fails validation", func(t *testing.T) {
		assert := assert.New(t)

		options, _ := data.GoMapToMapping(map[string]string{"host": "127.0.0.1"})
		transportType, _ := data.ToI2PString("SSU")
		cost, _ := data.NewIntegerFromInt(5, 1)

		ra := &RouterAddress{
			TransportCost:    cost,
			ExpirationDate:   nil,
			TransportType:    transportType,
			TransportOptions: options,
		}

		err := ra.Validate()
		assert.Error(err, "RouterAddress with nil expiration should fail validation")
		assert.Contains(err.Error(), "expiration date is required")
	})

	t.Run("router address with nil transport type fails validation", func(t *testing.T) {
		assert := assert.New(t)

		options, _ := data.GoMapToMapping(map[string]string{"host": "127.0.0.1"})
		cost, _ := data.NewIntegerFromInt(5, 1)
		expirationDate, _, _ := data.NewDate(make([]byte, data.DATE_SIZE))

		ra := &RouterAddress{
			TransportCost:    cost,
			ExpirationDate:   expirationDate,
			TransportType:    nil,
			TransportOptions: options,
		}

		err := ra.Validate()
		assert.Error(err, "RouterAddress with nil transport type should fail validation")
		assert.Contains(err.Error(), "transport type is required")
	})

	t.Run("router address with empty transport type fails validation", func(t *testing.T) {
		assert := assert.New(t)

		options, _ := data.GoMapToMapping(map[string]string{"host": "127.0.0.1"})
		cost, _ := data.NewIntegerFromInt(5, 1)
		expirationDate, _, _ := data.NewDate(make([]byte, data.DATE_SIZE))

		ra := &RouterAddress{
			TransportCost:    cost,
			ExpirationDate:   expirationDate,
			TransportType:    data.I2PString{},
			TransportOptions: options,
		}

		err := ra.Validate()
		assert.Error(err, "RouterAddress with empty transport type should fail validation")
		assert.Contains(err.Error(), "transport type is required")
	})

	t.Run("router address with nil transport options fails validation", func(t *testing.T) {
		assert := assert.New(t)

		transportType, _ := data.ToI2PString("SSU")
		cost, _ := data.NewIntegerFromInt(5, 1)
		expirationDate, _, _ := data.NewDate(make([]byte, data.DATE_SIZE))

		ra := &RouterAddress{
			TransportCost:    cost,
			ExpirationDate:   expirationDate,
			TransportType:    transportType,
			TransportOptions: nil,
		}

		err := ra.Validate()
		assert.Error(err, "RouterAddress with nil options should fail validation")
		assert.Contains(err.Error(), "transport options are required")
	})
}

func TestRouterAddressIsValid(t *testing.T) {
	t.Run("valid router address returns true", func(t *testing.T) {
		assert := assert.New(t)

		options := map[string]string{"host": "127.0.0.1", "port": "4567"}
		ra, err := NewRouterAddress(3, time.Now().Add(1*time.Hour), "SSU", options)
		assert.NoError(err)

		assert.True(ra.IsValid(), "Valid RouterAddress should return true for IsValid")
	})

	t.Run("nil router address returns false", func(t *testing.T) {
		assert := assert.New(t)

		var ra *RouterAddress
		assert.False(ra.IsValid(), "Nil RouterAddress should return false for IsValid")
	})

	t.Run("router address with missing fields returns false", func(t *testing.T) {
		assert := assert.New(t)

		ra := &RouterAddress{}
		assert.False(ra.IsValid(), "RouterAddress with missing fields should return false for IsValid")
	})
}

// =========================================================================
// Bytes() nil field guards
// =========================================================================

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

// =========================================================================
// Cost() and Expiration() nil guards
// =========================================================================

func TestCostReturnsZeroOnNilTransportCost(t *testing.T) {
	ra := RouterAddress{TransportCost: nil}
	assert.Equal(t, 0, ra.Cost(), "Cost() should return 0 when TransportCost is nil")
}

func TestExpirationReturnsZeroOnNilExpirationDate(t *testing.T) {
	ra := RouterAddress{ExpirationDate: nil}
	exp := ra.Expiration()
	assert.Equal(t, data.Date{}, exp, "Expiration() should return zero Date when ExpirationDate is nil")
}

// =========================================================================
// checkValid() Tests
// =========================================================================

func TestCheckValidReturnsBehavior(t *testing.T) {
	t.Run("valid address", func(t *testing.T) {
		ra, err := NewRouterAddress(5, time.Time{}, "NTCP2", map[string]string{"host": "127.0.0.1"})
		require.NoError(t, err)
		err = ra.checkValid()
		assert.NoError(t, err)
	})

	t.Run("nil transport type", func(t *testing.T) {
		ra := &RouterAddress{TransportType: nil}
		err := ra.checkValid()
		assert.Error(t, err)
	})

	t.Run("nil transport options", func(t *testing.T) {
		transportType, _ := data.ToI2PString("NTCP2")
		ra := &RouterAddress{TransportType: transportType, TransportOptions: nil}
		err := ra.checkValid()
		assert.Error(t, err)
	})
}

func TestCheckValidSignature(t *testing.T) {
	ra, err := NewRouterAddress(5, time.Time{}, "NTCP2", map[string]string{"host": "127.0.0.1"})
	require.NoError(t, err)

	e := ra.checkValid()
	assert.NoError(t, e)
}

// =========================================================================
// checkValid() from ReadRouterAddress
// =========================================================================

func TestCheckRouterAddressValidNoErrWithValidData(t *testing.T) {
	assert := assert.New(t)

	router_address, _, _ := ReadRouterAddress([]byte{0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00})
	mapping, err := data.GoMapToMapping(map[string]string{"host": "127.0.0.1", "port": "4567"})
	assert.Nil(err, "GoMapToMapping() returned error with valid data")
	router_address.TransportOptions = mapping
	err = router_address.checkValid()

	assert.Nil(err, "checkValid() reported error with valid data")
}

// =========================================================================
// Cost and Expiration from parsed data
// =========================================================================

func TestRouterAddressCostReturnsFirstByte(t *testing.T) {
	assert := assert.New(t)

	// Build wire data: cost=6, 8-byte expiration, I2PString "X", mapping size=0
	buf := []byte{0x06}
	buf = append(buf, make([]byte, 8)...)
	ts, _ := data.ToI2PString("X")
	buf = append(buf, ts...)
	buf = append(buf, 0x00, 0x00)

	router_address, _, err := ReadRouterAddress(buf)
	cost := router_address.Cost()

	assert.Nil(err, "Cost() returned error with valid data")
	assert.Equal(cost, 6, "Cost() returned wrong cost")
}

func TestRouterAddressExpirationReturnsCorrectData(t *testing.T) {
	assert := assert.New(t)

	// Build wire data: cost=0, 8-byte expiration (all zeros), I2PString "X", mapping size=0
	buf := []byte{0x00}
	buf = append(buf, make([]byte, 8)...)
	ts, _ := data.ToI2PString("X")
	buf = append(buf, ts...)
	buf = append(buf, 0x00, 0x00)

	router_address, _, err := ReadRouterAddress(buf)
	expiration := router_address.Expiration()

	assert.Nil(err, "Expiration() returned error with valid data")
	if bytes.Compare(expiration[:], []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}) != 0 {
		t.Fatal("Expiration did not return correct data:", expiration)
	}
}

// =========================================================================
// Options Tests
// =========================================================================

func TestOptionsReturnsValidMapping(t *testing.T) {
	ra, err := NewRouterAddress(5, time.Time{}, "NTCP2", map[string]string{
		"host": "127.0.0.1",
		"port": "9150",
	})
	require.NoError(t, err)

	opts := ra.Options()
	assert.NotNil(t, opts.Values(), "Options should return a mapping with values")
}

func TestOptionsNilTransportOptions(t *testing.T) {
	ra := RouterAddress{TransportOptions: nil}
	opts := ra.Options()
	assert.NotNil(t, &opts, "Options should return non-nil mapping even with nil TransportOptions")
}

// =========================================================================
// Receiver naming consistency (compilation verification)
// =========================================================================

func TestReceiverNamingConsistency(t *testing.T) {
	ra, err := NewRouterAddress(5, time.Time{}, "NTCP2", map[string]string{
		"host": "192.168.1.1",
		"port": "9150",
	})
	require.NoError(t, err)

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

	_ = ra.Network()
	_ = ra.IPVersion()
	_ = ra.UDP()
	_ = ra.String()
}

// =========================================================================
// Validate() sentinel errors
// =========================================================================

func TestSentinelErrors_ProgrammaticHandling(t *testing.T) {
	t.Run("ErrNilRouterAddress from Validate", func(t *testing.T) {
		var ra *RouterAddress
		err := ra.Validate()
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrNilRouterAddress), "Should be ErrNilRouterAddress, got: %v", err)
	})

	t.Run("ErrMissingTransportType from Validate", func(t *testing.T) {
		cost, _ := data.NewIntegerFromInt(5, 1)
		dateBytes := make([]byte, data.DATE_SIZE)
		expDate, _, _ := data.NewDate(dateBytes)
		opts, _ := data.GoMapToMapping(map[string]string{})
		ra := &RouterAddress{
			TransportCost:    cost,
			ExpirationDate:   expDate,
			TransportType:    nil,
			TransportOptions: opts,
		}
		err := ra.Validate()
		assert.True(t, errors.Is(err, ErrMissingTransportType), "Should be ErrMissingTransportType, got: %v", err)
	})

	t.Run("ErrMissingStaticKey from StaticKey", func(t *testing.T) {
		ra, err := NewRouterAddress(5, time.Time{}, "NTCP2", map[string]string{"host": "127.0.0.1"})
		require.NoError(t, err)
		_, skErr := ra.StaticKey()
		assert.True(t, errors.Is(skErr, ErrMissingStaticKey))
	})

	t.Run("ErrMissingInitializationVector from InitializationVector", func(t *testing.T) {
		ra, err := NewRouterAddress(5, time.Time{}, "NTCP2", map[string]string{"host": "127.0.0.1"})
		require.NoError(t, err)
		_, ivErr := ra.InitializationVector()
		assert.True(t, errors.Is(ivErr, ErrMissingInitializationVector))
	})
}

// =========================================================================
// NewRouterAddress option validation behavior
// =========================================================================

func TestNewRouterAddress_OptionValidation(t *testing.T) {
	t.Run("hostname accepted at construction and at accessor (per I2P spec)", func(t *testing.T) {
		ra, err := NewRouterAddress(5, time.Time{}, "NTCP2", map[string]string{
			"host": "router.example.i2p",
		})
		require.NoError(t, err, "Construction should succeed")
		host, hostErr := ra.Host()
		// hostname is now accepted per spec
		assert.NoError(t, hostErr, "Host() should accept valid hostnames per I2P spec")
		assert.Equal(t, "router.example.i2p", host.String())
	})

	t.Run("host with spaces rejected at accessor (invalid host format)", func(t *testing.T) {
		ra, err := NewRouterAddress(5, time.Time{}, "NTCP2", map[string]string{
			"host": "not an ip",
		})
		require.NoError(t, err, "Construction should succeed")
		_, hostErr := ra.Host()
		assert.Error(t, hostErr, "Host() should reject host string containing spaces")
	})

	t.Run("invalid port accepted at construction, rejected at accessor", func(t *testing.T) {
		ra, err := NewRouterAddress(5, time.Time{}, "NTCP2", map[string]string{
			"host": "127.0.0.1",
			"port": "abc",
		})
		require.NoError(t, err, "Construction should succeed")
		_, portErr := ra.Port()
		assert.Error(t, portErr, "Port() should reject non-numeric port")
	})

	t.Run("port out of range rejected at accessor", func(t *testing.T) {
		ra, err := NewRouterAddress(5, time.Time{}, "NTCP2", map[string]string{
			"host": "127.0.0.1",
			"port": "70000",
		})
		require.NoError(t, err, "Construction should succeed")
		_, portErr := ra.Port()
		assert.Error(t, portErr, "Port() should reject port > 65535")
	})
}

// =========================================================================
// createExpirationDate ignores parameter
// =========================================================================

func TestCreateExpirationDate_IgnoresParameter(t *testing.T) {
	t.Run("future time produces all-zero date", func(t *testing.T) {
		futureTime := time.Date(2030, 6, 15, 12, 0, 0, 0, time.UTC)
		ra, err := NewRouterAddress(5, futureTime, "NTCP2", map[string]string{})
		require.NoError(t, err)
		assert.False(t, ra.HasNonZeroExpiration(), "Expiration should be all zeros regardless of input time")
	})

	t.Run("past time produces all-zero date", func(t *testing.T) {
		pastTime := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
		ra, err := NewRouterAddress(5, pastTime, "NTCP2", map[string]string{})
		require.NoError(t, err)
		assert.False(t, ra.HasNonZeroExpiration())
	})
}

// =========================================================================
// BUG-1: Validate() rejects zero-content-length I2PString TransportType
// =========================================================================

func TestValidateRejectsZeroContentLengthTransportType(t *testing.T) {
	cost, _ := data.NewIntegerFromInt(5, 1)
	expDate, _, _ := data.NewDate(make([]byte, data.DATE_SIZE))
	mapping, _ := data.GoMapToMapping(map[string]string{})

	t.Run("I2PString{0x00} rejected by Validate", func(t *testing.T) {
		ra := &RouterAddress{
			TransportCost:    cost,
			ExpirationDate:   expDate,
			TransportType:    data.I2PString{0x00}, // zero-content I2PString
			TransportOptions: mapping,
		}
		err := ra.Validate()
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrEmptyTransportStyle)
	})

	t.Run("I2PString{0x00} rejected by Serialize", func(t *testing.T) {
		ra := &RouterAddress{
			TransportCost:    cost,
			ExpirationDate:   expDate,
			TransportType:    data.I2PString{0x00},
			TransportOptions: mapping,
		}
		b, err := ra.Serialize()
		assert.Nil(t, b)
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrEmptyTransportStyle)
	})

	t.Run("well-formed I2PString passes Validate", func(t *testing.T) {
		ts, _ := data.ToI2PString("NTCP2")
		ra := &RouterAddress{
			TransportCost:    cost,
			ExpirationDate:   expDate,
			TransportType:    ts,
			TransportOptions: mapping,
		}
		err := ra.Validate()
		assert.NoError(t, err)
	})
}
