package router_address

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// =========================================================================
// HasValidHost() Tests
// =========================================================================

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

// =========================================================================
// HasValidPort() Tests
// =========================================================================

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

// =========================================================================
// Combined Defensive Programming Pattern Test
// =========================================================================

func TestDefensiveProgrammingPattern(t *testing.T) {
	assert := assert.New(t)

	addresses := []map[string]string{
		{"host": "192.168.1.1", "port": "9150"},
		{"host": "bad-host", "port": "9150"},
		{"host": "192.168.1.2", "port": "abc"},
		{"port": "9150"},
		{"host": "192.168.1.3"},
		{"host": "10.0.0.1", "port": "8080"},
	}

	var validAddresses []*RouterAddress
	for _, opts := range addresses {
		ra, err := NewRouterAddress(3, time.Now().Add(1*time.Hour), "SSU", opts)
		assert.NoError(err)

		if !ra.HasValidHost() || !ra.HasValidPort() {
			continue
		}

		validAddresses = append(validAddresses, ra)
	}

	assert.Len(validAddresses, 2, "Should have filtered to only valid addresses")

	for _, ra := range validAddresses {
		host, err := ra.Host()
		assert.NoError(err, "Host() should not error on pre-validated address")
		assert.NotNil(host)

		port, err := ra.Port()
		assert.NoError(err, "Port() should not error on pre-validated address")
		assert.NotEmpty(port)
	}
}
