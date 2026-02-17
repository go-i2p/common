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

	// 1 (cost=0x06) + 8 (expiration=zeros) + 1 (string len=0x01) + 1 (string data=0x00) + 2 (mapping size=0x0000) = 13 bytes
	router_address, _, _ := ReadRouterAddress([]byte{0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00})
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

	// 1 (cost=0x06) + 8 (expiration=zeros) + 1 (string len=0x00) + 2 (mapping size=0x0000) = 12 bytes
	router_address, _, err := ReadRouterAddress([]byte{0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	cost := router_address.Cost()

	assert.Nil(err, "Cost() returned error with valid data")
	assert.Equal(cost, 6, "Cost() returned wrong cost")
}

func TestRouterAddressExpirationReturnsCorrectData(t *testing.T) {
	assert := assert.New(t)

	// Per I2P spec, expiration must be all zeros
	// 1 (cost=0x00) + 8 (expiration=zeros) + 1 (string len=0x00) + 2 (mapping size=0x0000) = 12 bytes
	router_address, _, err := ReadRouterAddress([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	expiration := router_address.Expiration()

	assert.Nil(err, "Expiration() returned error with valid data")
	if bytes.Compare(expiration[:], []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}) != 0 {
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

//
// Host() Method Tests
//

// TestHost_MissingKey tests that Host() returns clear error when host key is missing
func TestHost_MissingKey(t *testing.T) {
	assert := assert.New(t)

	options := map[string]string{
		"port": "12345",
		// "host" intentionally missing
	}
	ra, err := NewRouterAddress(3, time.Now().Add(1*time.Hour), "SSU", options)
	assert.NoError(err, "NewRouterAddress should not fail with missing host")

	_, err = ra.Host()
	assert.Error(err, "Host() should return error when host key is missing")
	assert.Contains(err.Error(), "missing required 'host' key", "Error should indicate missing host key")
}

// TestHost_EmptyValue tests that Host() returns clear error when host value is empty
func TestHost_EmptyValue(t *testing.T) {
	assert := assert.New(t)

	options := map[string]string{
		"host": "",
		"port": "12345",
	}
	ra, err := NewRouterAddress(3, time.Now().Add(1*time.Hour), "SSU", options)
	assert.NoError(err)

	_, err = ra.Host()
	assert.Error(err, "Host() should return error when host is empty")
	assert.Contains(err.Error(), "is empty", "Error should indicate empty value")
}

// TestHost_InvalidIP tests that Host() returns clear error when IP is invalid
func TestHost_InvalidIP(t *testing.T) {
	assert := assert.New(t)

	testCases := []struct {
		name     string
		hostVal  string
		errMatch string
	}{
		{"not an ip", "not-an-ip", "invalid IP address"},
		{"invalid format", "999.999.999.999", "invalid IP address"},
		{"hostname", "example.com", "invalid IP address"},
		{"partial ip", "192.168.1", "invalid IP address"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			options := map[string]string{
				"host": tc.hostVal,
				"port": "12345",
			}
			ra, err := NewRouterAddress(3, time.Now().Add(1*time.Hour), "SSU", options)
			assert.NoError(err)

			_, err = ra.Host()
			assert.Error(err, "Host() should return error for invalid IP")
			assert.Contains(err.Error(), tc.errMatch, "Error should indicate invalid IP")
			assert.Contains(err.Error(), tc.hostVal, "Error should include the invalid value")
		})
	}
}

// TestHost_ValidIPv4 tests that Host() works correctly with valid IPv4 addresses
func TestHost_ValidIPv4(t *testing.T) {
	assert := assert.New(t)

	testCases := []string{
		"192.168.1.1",
		"127.0.0.1",
		"10.0.0.1",
		"8.8.8.8",
	}

	for _, ip := range testCases {
		t.Run(ip, func(t *testing.T) {
			options := map[string]string{
				"host": ip,
				"port": "12345",
			}
			ra, err := NewRouterAddress(3, time.Now().Add(1*time.Hour), "SSU", options)
			assert.NoError(err)

			host, err := ra.Host()
			assert.NoError(err, "Host() should not return error for valid IPv4")
			assert.NotNil(host, "Host should not be nil")
			assert.Equal(ip, host.String(), "Host string should match input IP")
		})
	}
}

// TestHost_ValidIPv6 tests that Host() works correctly with valid IPv6 addresses
func TestHost_ValidIPv6(t *testing.T) {
	assert := assert.New(t)

	testCases := []struct {
		input    string
		expected string
	}{
		{"::1", "::1"},
		{"2001:0db8:85a3:0000:0000:8a2e:0370:7334", "2001:db8:85a3::8a2e:370:7334"},
		{"fe80::1", "fe80::1"},
	}

	for _, tc := range testCases {
		t.Run(tc.input, func(t *testing.T) {
			options := map[string]string{
				"host": tc.input,
				"port": "12345",
			}
			ra, err := NewRouterAddress(3, time.Now().Add(1*time.Hour), "SSU", options)
			assert.NoError(err)

			host, err := ra.Host()
			assert.NoError(err, "Host() should not return error for valid IPv6")
			assert.NotNil(host, "Host should not be nil")
			assert.Equal(tc.expected, host.String(), "Host string should match expected normalized IPv6")
		})
	}
}

//
// Port() Method Tests
//

// TestPort_MissingKey tests that Port() returns clear error when port key is missing
func TestPort_MissingKey(t *testing.T) {
	assert := assert.New(t)

	options := map[string]string{
		"host": "192.168.1.1",
		// "port" intentionally missing
	}
	ra, err := NewRouterAddress(3, time.Now().Add(1*time.Hour), "SSU", options)
	assert.NoError(err, "NewRouterAddress should not fail with missing port")

	_, err = ra.Port()
	assert.Error(err, "Port() should return error when port key is missing")
	assert.Contains(err.Error(), "missing required 'port' key", "Error should indicate missing port key")
}

// TestPort_EmptyValue tests that Port() returns clear error when port value is empty
func TestPort_EmptyValue(t *testing.T) {
	assert := assert.New(t)

	options := map[string]string{
		"host": "192.168.1.1",
		"port": "",
	}
	ra, err := NewRouterAddress(3, time.Now().Add(1*time.Hour), "SSU", options)
	assert.NoError(err)

	_, err = ra.Port()
	assert.Error(err, "Port() should return error when port is empty")
	assert.Contains(err.Error(), "is empty", "Error should indicate empty value")
}

// TestPort_InvalidNumber tests that Port() returns clear error when port is not a valid number
func TestPort_InvalidNumber(t *testing.T) {
	assert := assert.New(t)

	testCases := []struct {
		name     string
		portVal  string
		errMatch string
	}{
		{"not a number", "abc", "not a valid number"},
		{"float", "123.45", "not a valid number"},
		{"with spaces", "123 456", "not a valid number"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			options := map[string]string{
				"host": "192.168.1.1",
				"port": tc.portVal,
			}
			ra, err := NewRouterAddress(3, time.Now().Add(1*time.Hour), "SSU", options)
			assert.NoError(err)

			_, err = ra.Port()
			assert.Error(err, "Port() should return error for invalid number")
			assert.Contains(err.Error(), tc.errMatch, "Error should indicate invalid number")
		})
	}
}

// TestPort_OutOfRange tests that Port() returns clear error when port is out of valid range
func TestPort_OutOfRange(t *testing.T) {
	assert := assert.New(t)

	testCases := []struct {
		name    string
		portVal string
	}{
		{"zero", "0"},
		{"negative", "-1"},
		{"too high", "65536"},
		{"way too high", "99999"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			options := map[string]string{
				"host": "192.168.1.1",
				"port": tc.portVal,
			}
			ra, err := NewRouterAddress(3, time.Now().Add(1*time.Hour), "SSU", options)
			assert.NoError(err)

			_, err = ra.Port()
			assert.Error(err, "Port() should return error for out-of-range port")
			assert.Contains(err.Error(), "out of valid range", "Error should indicate out of range")
		})
	}
}

// TestPort_ValidPort tests that Port() works correctly with valid port numbers
func TestPort_ValidPort(t *testing.T) {
	assert := assert.New(t)

	testCases := []string{
		"1",     // minimum valid port
		"80",    // common port
		"443",   // common port
		"8080",  // common port
		"12345", // arbitrary valid port
		"65535", // maximum valid port
	}

	for _, port := range testCases {
		t.Run(port, func(t *testing.T) {
			options := map[string]string{
				"host": "192.168.1.1",
				"port": port,
			}
			ra, err := NewRouterAddress(3, time.Now().Add(1*time.Hour), "SSU", options)
			assert.NoError(err)

			portStr, err := ra.Port()
			assert.NoError(err, "Port() should not return error for valid port")
			assert.Equal(port, portStr, "Port string should match input")
		})
	}
}

//
// HasValidHost() Helper Tests
//

// TestHasValidHost tests the HasValidHost() helper method
func TestHasValidHost(t *testing.T) {
	tests := []struct {
		name     string
		options  map[string]string
		expected bool
	}{
		{"missing host key", map[string]string{"port": "12345"}, false},
		{"empty host", map[string]string{"host": "", "port": "12345"}, false},
		{"invalid IP - text", map[string]string{"host": "not-an-ip", "port": "12345"}, false},
		{"invalid IP - malformed", map[string]string{"host": "999.999.999.999", "port": "12345"}, false},
		{"valid IPv4", map[string]string{"host": "192.168.1.1", "port": "12345"}, true},
		{"valid IPv4 - localhost", map[string]string{"host": "127.0.0.1", "port": "12345"}, true},
		{"valid IPv6", map[string]string{"host": "::1", "port": "12345"}, true},
		{"valid IPv6 - full", map[string]string{"host": "2001:0db8:85a3:0000:0000:8a2e:0370:7334", "port": "12345"}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)

			ra, err := NewRouterAddress(3, time.Now().Add(1*time.Hour), "SSU", tt.options)
			assert.NoError(err, "NewRouterAddress should not fail")

			result := ra.HasValidHost()
			assert.Equal(tt.expected, result, "HasValidHost() returned unexpected result")
		})
	}
}

//
// HasValidPort() Helper Tests
//

// TestHasValidPort tests the HasValidPort() helper method
func TestHasValidPort(t *testing.T) {
	tests := []struct {
		name     string
		options  map[string]string
		expected bool
	}{
		{"missing port key", map[string]string{"host": "192.168.1.1"}, false},
		{"empty port", map[string]string{"host": "192.168.1.1", "port": ""}, false},
		{"invalid - not a number", map[string]string{"host": "192.168.1.1", "port": "abc"}, false},
		{"invalid - zero", map[string]string{"host": "192.168.1.1", "port": "0"}, false},
		{"invalid - negative", map[string]string{"host": "192.168.1.1", "port": "-1"}, false},
		{"invalid - too high", map[string]string{"host": "192.168.1.1", "port": "65536"}, false},
		{"valid - minimum", map[string]string{"host": "192.168.1.1", "port": "1"}, true},
		{"valid - common", map[string]string{"host": "192.168.1.1", "port": "8080"}, true},
		{"valid - maximum", map[string]string{"host": "192.168.1.1", "port": "65535"}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)

			ra, err := NewRouterAddress(3, time.Now().Add(1*time.Hour), "SSU", tt.options)
			assert.NoError(err, "NewRouterAddress should not fail")

			result := ra.HasValidPort()
			assert.Equal(tt.expected, result, "HasValidPort() returned unexpected result")
		})
	}
}

//
// Combined Validation Tests
//

// TestDefensiveProgrammingPattern demonstrates the intended usage pattern
func TestDefensiveProgrammingPattern(t *testing.T) {
	assert := assert.New(t)

	// Create a slice of RouterAddresses with various states
	addresses := []map[string]string{
		{"host": "192.168.1.1", "port": "9150"}, // valid
		{"host": "bad-host", "port": "9150"},    // invalid host
		{"host": "192.168.1.2", "port": "abc"},  // invalid port
		{"port": "9150"},                        // missing host
		{"host": "192.168.1.3"},                 // missing port
		{"host": "10.0.0.1", "port": "8080"},    // valid
	}

	var validAddresses []*RouterAddress
	for _, opts := range addresses {
		ra, err := NewRouterAddress(3, time.Now().Add(1*time.Hour), "SSU", opts)
		assert.NoError(err)

		// Defensive programming: skip invalid addresses gracefully
		if !ra.HasValidHost() || !ra.HasValidPort() {
			continue
		}

		validAddresses = append(validAddresses, ra)
	}

	// Should have found exactly 2 valid addresses
	assert.Len(validAddresses, 2, "Should have filtered to only valid addresses")

	// Verify we can call Host() and Port() without errors on filtered addresses
	for _, ra := range validAddresses {
		host, err := ra.Host()
		assert.NoError(err, "Host() should not error on pre-validated address")
		assert.NotNil(host)

		port, err := ra.Port()
		assert.NoError(err, "Port() should not error on pre-validated address")
		assert.NotEmpty(port)
	}
}
