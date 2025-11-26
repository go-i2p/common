package router_address

import (
	"bytes"
	"testing"
	"time"

	"github.com/go-i2p/common/data"
	"github.com/stretchr/testify/assert"
)

/*
func TestCheckValidReportsEmptySlice(t *testing.T) {
	assert := assert.New(t)

	router_address, _, err := ReadRouterAddress([]byte{})

	if assert.NotNil(err) {
		assert.Equal(err.Error(), "error parsing RouterAddress: no data", "correct error message should be returned")
	}
	err, exit := router_address.checkValid()
	assert.Equal(exit, true, "checkValid did not indicate to stop parsing on empty slice")
}

func TestCheckRouterAddressValidReportsDataMissing(t *testing.T) {
	assert := assert.New(t)

	router_address, _, err := ReadRouterAddress([]byte{0x01})

	if assert.NotNil(err) {
		assert.Equal(err.Error(), "warning parsing RouterAddress: data too small", "correct error message should be returned")
	}

	err, exit := router_address.checkValid()
	assert.Equal(exit, false, "checkValid indicates to stop parsing when some fields  may be present")
}

*/

func TestCheckRouterAddressValidNoErrWithValidData(t *testing.T) {
	assert := assert.New(t)

	router_address, _, _ := ReadRouterAddress([]byte{0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00})
	mapping, err := data.GoMapToMapping(map[string]string{"host": "127.0.0.1", "port": "4567"})
	assert.Nil(err, "GoMapToMapping() returned error with valid data")
	router_address.TransportOptions = mapping
	// router_address = append(router_address, mapping...)
	err, exit := router_address.checkValid()

	assert.Nil(err, "checkValid() reported error with valid data")
	assert.Equal(exit, false, "checkValid() indicated to stop parsing valid data")
}

func TestRouterAddressCostReturnsFirstByte(t *testing.T) {
	assert := assert.New(t)

	router_address, _, err := ReadRouterAddress([]byte{0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00})
	cost := router_address.Cost()

	assert.Nil(err, "Cost() returned error with valid data")
	assert.Equal(cost, 6, "Cost() returned wrong cost")
}

func TestRouterAddressExpirationReturnsCorrectData(t *testing.T) {
	assert := assert.New(t)

	router_address, _, err := ReadRouterAddress([]byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x00})
	expiration := router_address.Expiration()

	assert.Nil(err, "Expiration() returned error with valid data")
	if bytes.Compare(expiration[:], []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}) != 0 {
		t.Fatal("Expiration did not return correct data:", expiration)
	}
}

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
	assert.Equal(0, bytes.Compare(remainder, []byte{0x01, 0x02, 0x03}))

	err, exit := router_address.checkValid()
	assert.Nil(err, "checkValid() on address from ReadRouterAddress() reported error with valid data")
	assert.Equal(exit, false, "checkValid() on address from ReadRouterAddress() indicated to stop parsing valid data")
}

func TestCorrectsFuzzCrasher1(t *testing.T) {
	assert := assert.New(t)

	defer func() {
		if r := recover(); r != nil {
			assert.Equal(nil, r)
		}
	}()

	router_address_bytes := []byte{0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x00, 0x30, 0x30}
	ReadRouterAddress(router_address_bytes)
}

//
// Constructor Tests
//

// TestNewRouterAddressValid tests creating a valid RouterAddress
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

// TestNewRouterAddressEmptyTransportType tests that empty transport type is rejected
func TestNewRouterAddressEmptyTransportType(t *testing.T) {
	assert := assert.New(t)

	options := map[string]string{"host": "192.168.1.1"}
	expiration := time.Now().Add(24 * time.Hour)

	ra, err := NewRouterAddress(5, expiration, "", options)

	assert.Error(err, "NewRouterAddress should return error with empty transport type")
	assert.Nil(ra, "RouterAddress should be nil on error")
	assert.Contains(err.Error(), "transport type cannot be empty")
}

// TestNewRouterAddressNilOptions tests that nil options are handled
func TestNewRouterAddressNilOptions(t *testing.T) {
	assert := assert.New(t)

	expiration := time.Now().Add(24 * time.Hour)

	ra, err := NewRouterAddress(5, expiration, "NTCP2", nil)

	// nil options should be converted to empty mapping
	assert.NoError(err, "NewRouterAddress should handle nil options")
	assert.NotNil(ra, "RouterAddress should not be nil")
}

// TestNewRouterAddressEmptyOptions tests that empty options map works
func TestNewRouterAddressEmptyOptions(t *testing.T) {
	assert := assert.New(t)

	options := map[string]string{}
	expiration := time.Now().Add(24 * time.Hour)

	ra, err := NewRouterAddress(5, expiration, "NTCP2", options)

	assert.NoError(err, "NewRouterAddress should work with empty options")
	assert.NotNil(ra, "RouterAddress should not be nil")
}

//
// Validation Tests
//

// TestRouterAddressValidate tests the Validate method
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

// TestRouterAddressIsValid tests the IsValid convenience method
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
