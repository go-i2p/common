package router_address

import (
	"encoding/base64"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	i2pbase64 "github.com/go-i2p/common/base64"
	"github.com/go-i2p/common/data"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =========================================================================
// Network() Tests
// =========================================================================

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

func TestNetworkWithoutIPVersion(t *testing.T) {
	t.Run("no host and no caps returns transport only", func(t *testing.T) {
		ra, err := NewRouterAddress(5, time.Time{}, "NTCP2", map[string]string{})
		require.NoError(t, err)
		network := ra.Network()
		assert.Equal(t, "NTCP2", network, "Network should return just the transport type without version suffix")
	})

	t.Run("with IPv4 host includes version", func(t *testing.T) {
		ra, err := NewRouterAddress(5, time.Time{}, "NTCP2", map[string]string{
			"host": "192.168.1.1",
		})
		require.NoError(t, err)
		assert.Equal(t, "NTCP24", ra.Network())
	})

	t.Run("with IPv6 host includes version", func(t *testing.T) {
		ra, err := NewRouterAddress(5, time.Time{}, "NTCP2", map[string]string{
			"host": "::1",
		})
		require.NoError(t, err)
		assert.Equal(t, "NTCP26", ra.Network())
	})
}

// =========================================================================
// IPVersion() Tests
// =========================================================================

func TestIPVersionMethod(t *testing.T) {
	t.Run("IPv4 with caps", func(t *testing.T) {
		ra, err := NewRouterAddress(5, time.Time{}, "NTCP2", map[string]string{
			"host": "127.0.0.1",
			"caps": "BC",
		})
		require.NoError(t, err)
		assert.Equal(t, IPV4_VERSION_STRING, ra.IPVersion())
	})

	t.Run("no caps returns version from host", func(t *testing.T) {
		ra, err := NewRouterAddress(5, time.Time{}, "NTCP2", map[string]string{
			"host": "127.0.0.1",
		})
		require.NoError(t, err)
		assert.Equal(t, IPV4_VERSION_STRING, ra.IPVersion())
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

func TestIPVersionFromHost(t *testing.T) {
	t.Run("IPv4 host detected without caps", func(t *testing.T) {
		ra, err := NewRouterAddress(5, time.Time{}, "NTCP2", map[string]string{
			"host": "192.168.1.1",
		})
		require.NoError(t, err)
		assert.Equal(t, IPV4_VERSION_STRING, ra.IPVersion())
	})

	t.Run("IPv6 host detected without caps", func(t *testing.T) {
		ra, err := NewRouterAddress(5, time.Time{}, "NTCP2", map[string]string{
			"host": "2001:db8::1",
		})
		require.NoError(t, err)
		assert.Equal(t, IPV6_VERSION_STRING, ra.IPVersion())
	})

	t.Run("IPv6 loopback detected without caps", func(t *testing.T) {
		ra, err := NewRouterAddress(5, time.Time{}, "NTCP2", map[string]string{
			"host": "::1",
		})
		require.NoError(t, err)
		assert.Equal(t, IPV6_VERSION_STRING, ra.IPVersion())
	})

	t.Run("IPv4 loopback detected without caps", func(t *testing.T) {
		ra, err := NewRouterAddress(5, time.Time{}, "NTCP2", map[string]string{
			"host": "127.0.0.1",
		})
		require.NoError(t, err)
		assert.Equal(t, IPV4_VERSION_STRING, ra.IPVersion())
	})

	t.Run("falls back to caps when no host", func(t *testing.T) {
		ra, err := NewRouterAddress(5, time.Time{}, "NTCP2", map[string]string{
			"caps": "BC6",
		})
		require.NoError(t, err)
		assert.Equal(t, IPV6_VERSION_STRING, ra.IPVersion())
	})

	t.Run("falls back to caps IPv4 when no host", func(t *testing.T) {
		ra, err := NewRouterAddress(5, time.Time{}, "NTCP2", map[string]string{
			"caps": "BC",
		})
		require.NoError(t, err)
		assert.Equal(t, IPV4_VERSION_STRING, ra.IPVersion())
	})

	t.Run("empty string when no host and no caps", func(t *testing.T) {
		ra, err := NewRouterAddress(5, time.Time{}, "NTCP2", map[string]string{})
		require.NoError(t, err)
		assert.Equal(t, "", ra.IPVersion())
	})

	t.Run("host takes precedence over caps", func(t *testing.T) {
		ra, err := NewRouterAddress(5, time.Time{}, "NTCP2", map[string]string{
			"host": "::1",
			"caps": "BC",
		})
		require.NoError(t, err)
		assert.Equal(t, IPV6_VERSION_STRING, ra.IPVersion())
	})
}

// =========================================================================
// UDP() Tests
// =========================================================================

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

// =========================================================================
// String() Tests
// =========================================================================

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

func TestStringNilSafety(t *testing.T) {
	t.Run("zero-value RouterAddress produces empty string without panic", func(t *testing.T) {
		ra := &RouterAddress{}
		assert.NotPanics(t, func() {
			result := ra.String()
			assert.Equal(t, "", result)
		})
	})

	t.Run("nil TransportType produces empty string", func(t *testing.T) {
		ra := &RouterAddress{TransportType: nil}
		assert.NotPanics(t, func() {
			result := ra.String()
			assert.Equal(t, "", result)
		})
	})

	t.Run("nil pointer RouterAddress produces empty string", func(t *testing.T) {
		var ra *RouterAddress
		assert.NotPanics(t, func() {
			result := ra.String()
			assert.Equal(t, "", result)
		})
	})

	t.Run("partially initialized RouterAddress", func(t *testing.T) {
		transportType, _ := data.ToI2PString("NTCP2")
		ra := &RouterAddress{
			TransportType:    transportType,
			TransportOptions: nil,
		}
		assert.NotPanics(t, func() {
			result := ra.String()
			assert.Contains(t, result, "NTCP2")
		})
	})
}

// =========================================================================
// Host() Tests
// =========================================================================

func TestHost_MissingKey(t *testing.T) {
	assert := assert.New(t)

	options := map[string]string{"port": "12345"}
	ra, err := NewRouterAddress(3, time.Now().Add(1*time.Hour), "SSU", options)
	assert.NoError(err, "NewRouterAddress should not fail with missing host")

	_, err = ra.Host()
	assert.Error(err, "Host() should return error when host key is missing")
	assert.Contains(err.Error(), "missing required 'host' key", "Error should indicate missing host key")
}

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

func TestHost_InvalidIP(t *testing.T) {
	assert := assert.New(t)

	testCases := []struct {
		name     string
		hostVal  string
		errMatch string
	}{
		// These contain characters that are invalid in both IP literals and
		// hostnames (RFC 1123): spaces, underscores, etc.
		{"space in value", "not an ip", "invalid host"},
		{"underscore", "bad_host", "invalid host"},
		{"at-sign", "user@host", "invalid host"},
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
			assert.Error(err, "Host() should return error for invalid host")
			assert.Contains(err.Error(), tc.errMatch, "Error should indicate invalid host")
		})
	}
}

func TestHost_ValidIPv4(t *testing.T) {
	assert := assert.New(t)

	testCases := []string{"192.168.1.1", "127.0.0.1", "10.0.0.1", "8.8.8.8"}

	for _, ip := range testCases {
		t.Run(ip, func(t *testing.T) {
			options := map[string]string{"host": ip, "port": "12345"}
			ra, err := NewRouterAddress(3, time.Now().Add(1*time.Hour), "SSU", options)
			assert.NoError(err)

			host, err := ra.Host()
			assert.NoError(err, "Host() should not return error for valid IPv4")
			assert.NotNil(host, "Host should not be nil")
			assert.Equal(ip, host.String(), "Host string should match input IP")
		})
	}
}

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
			options := map[string]string{"host": tc.input, "port": "12345"}
			ra, err := NewRouterAddress(3, time.Now().Add(1*time.Hour), "SSU", options)
			assert.NoError(err)

			host, err := ra.Host()
			assert.NoError(err, "Host() should not return error for valid IPv6")
			assert.NotNil(host, "Host should not be nil")
			assert.Equal(tc.expected, host.String(), "Host string should match expected normalized IPv6")
		})
	}
}

// TestHostAcceptsHostnames verifies that Host() accepts valid hostname strings
// per the I2P specification ("an IPv4 or IPv6 address or host name").
func TestHostAcceptsHostnames(t *testing.T) {
	t.Run("i2p hostname accepted", func(t *testing.T) {
		ra, err := NewRouterAddress(5, time.Time{}, "NTCP2", map[string]string{
			"host": "example.i2p",
		})
		require.NoError(t, err)
		host, err := ra.Host()
		assert.NoError(t, err, "Host() should accept i2p hostnames per spec")
		assert.Equal(t, "example.i2p", host.String())
		assert.Equal(t, "host", host.Network())
	})

	t.Run("dotted hostname accepted", func(t *testing.T) {
		ra, err := NewRouterAddress(5, time.Time{}, "NTCP2", map[string]string{
			"host": "router.example.com",
		})
		require.NoError(t, err)
		host, err := ra.Host()
		assert.NoError(t, err, "Host() should accept dotted hostnames per spec")
		assert.Equal(t, "router.example.com", host.String())
	})

	t.Run("IP address still accepted", func(t *testing.T) {
		ra, err := NewRouterAddress(5, time.Time{}, "NTCP2", map[string]string{
			"host": "192.168.1.1",
		})
		require.NoError(t, err)
		host, err := ra.Host()
		assert.NoError(t, err)
		assert.NotNil(t, host)
		assert.Equal(t, "192.168.1.1", host.String())
	})

	t.Run("host with invalid characters rejected", func(t *testing.T) {
		ra, err := NewRouterAddress(5, time.Time{}, "NTCP2", map[string]string{
			"host": "not an ip",
		})
		require.NoError(t, err)
		_, err = ra.Host()
		assert.Error(t, err, "Host() should reject hosts with spaces")
	})
}

// =========================================================================
// Port() Tests
// =========================================================================

func TestPort_MissingKey(t *testing.T) {
	assert := assert.New(t)

	options := map[string]string{"host": "192.168.1.1"}
	ra, err := NewRouterAddress(3, time.Now().Add(1*time.Hour), "SSU", options)
	assert.NoError(err, "NewRouterAddress should not fail with missing port")

	_, err = ra.Port()
	assert.Error(err, "Port() should return error when port key is missing")
	assert.Contains(err.Error(), "missing required 'port' key", "Error should indicate missing port key")
}

func TestPort_EmptyValue(t *testing.T) {
	assert := assert.New(t)

	options := map[string]string{"host": "192.168.1.1", "port": ""}
	ra, err := NewRouterAddress(3, time.Now().Add(1*time.Hour), "SSU", options)
	assert.NoError(err)

	_, err = ra.Port()
	assert.Error(err, "Port() should return error when port is empty")
	assert.Contains(err.Error(), "is empty", "Error should indicate empty value")
}

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
			options := map[string]string{"host": "192.168.1.1", "port": tc.portVal}
			ra, err := NewRouterAddress(3, time.Now().Add(1*time.Hour), "SSU", options)
			assert.NoError(err)

			_, err = ra.Port()
			assert.Error(err, "Port() should return error for invalid number")
			assert.Contains(err.Error(), tc.errMatch, "Error should indicate invalid number")
		})
	}
}

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
			options := map[string]string{"host": "192.168.1.1", "port": tc.portVal}
			ra, err := NewRouterAddress(3, time.Now().Add(1*time.Hour), "SSU", options)
			assert.NoError(err)

			_, err = ra.Port()
			assert.Error(err, "Port() should return error for out-of-range port")
			assert.Contains(err.Error(), "out of valid range", "Error should indicate out of range")
		})
	}
}

func TestPort_ValidPort(t *testing.T) {
	assert := assert.New(t)

	testCases := []string{"1", "80", "443", "8080", "12345", "65535"}

	for _, port := range testCases {
		t.Run(port, func(t *testing.T) {
			options := map[string]string{"host": "192.168.1.1", "port": port}
			ra, err := NewRouterAddress(3, time.Now().Add(1*time.Hour), "SSU", options)
			assert.NoError(err)

			portStr, err := ra.Port()
			assert.NoError(err, "Port() should not return error for valid port")
			assert.Equal(port, portStr, "Port string should match input")
		})
	}
}

// =========================================================================
// StaticKey(), InitializationVector(), ProtocolVersion() Tests
// =========================================================================

func TestStaticKeyExcludesLengthPrefix(t *testing.T) {
	t.Run("base64-encoded 32-byte key succeeds after decode", func(t *testing.T) {
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

		result, err := ra.StaticKey()
		assert.NoError(t, err, "StaticKey should succeed for base64-encoded 32-byte data")
		assert.Equal(t, keyData, result[:], "Decoded key should match original")
	})

	t.Run("wrong-length raw value returns error", func(t *testing.T) {
		options := map[string]string{
			"host": "127.0.0.1",
			"port": "9150",
			"s":    "short",
		}
		ra, err := NewRouterAddress(5, time.Time{}, "NTCP2", options)
		require.NoError(t, err)

		_, err = ra.StaticKey()
		assert.Error(t, err, "StaticKey should fail for wrong-length data")
	})
}

func TestStaticKeyNotFound(t *testing.T) {
	options := map[string]string{"host": "127.0.0.1", "port": "9150"}
	ra, err := NewRouterAddress(5, time.Time{}, "NTCP2", options)
	require.NoError(t, err)

	_, err = ra.StaticKey()
	assert.Error(t, err, "StaticKey should return error when key 's' is missing")
	assert.Contains(t, err.Error(), "not found")
}

func TestInitializationVectorNotFound(t *testing.T) {
	options := map[string]string{"host": "127.0.0.1", "port": "9150"}
	ra, err := NewRouterAddress(5, time.Time{}, "NTCP2", options)
	require.NoError(t, err)

	_, err = ra.InitializationVector()
	assert.Error(t, err, "InitializationVector should return error when key 'i' is missing")
	assert.Contains(t, err.Error(), "not found")
}

func TestInitializationVectorInvalidSize(t *testing.T) {
	options := map[string]string{"host": "127.0.0.1", "port": "9150", "i": "tooshort"}
	ra, err := NewRouterAddress(5, time.Time{}, "NTCP2", options)
	require.NoError(t, err)

	_, err = ra.InitializationVector()
	assert.Error(t, err, "InitializationVector should fail for wrong-size data")
	assert.Contains(t, err.Error(), "invalid initialization vector length")
}

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
		_ = err
	})
}

// =========================================================================
// GetOption(), HasOption(), CheckOption() Tests
// =========================================================================

func TestGetOptionDirectTests(t *testing.T) {
	t.Run("GetOption returns nil for missing key", func(t *testing.T) {
		ra, err := NewRouterAddress(5, time.Time{}, "NTCP2", map[string]string{"host": "127.0.0.1"})
		require.NoError(t, err)
		key, _ := data.ToI2PString("nonexistent")
		result := ra.GetOption(key)
		assert.Nil(t, result, "GetOption should return nil for missing key")
	})

	t.Run("GetOption returns value for existing key", func(t *testing.T) {
		ra, err := NewRouterAddress(5, time.Time{}, "NTCP2", map[string]string{"host": "127.0.0.1"})
		require.NoError(t, err)
		key, _ := data.ToI2PString("host")
		result := ra.GetOption(key)
		assert.NotNil(t, result, "GetOption should return value for existing key")
		resultData, _ := result.Data()
		assert.Equal(t, "127.0.0.1", resultData)
	})

	t.Run("HasOption returns false for missing key", func(t *testing.T) {
		ra, err := NewRouterAddress(5, time.Time{}, "NTCP2", map[string]string{"host": "127.0.0.1"})
		require.NoError(t, err)
		key, _ := data.ToI2PString("missing")
		assert.False(t, ra.HasOption(key))
	})

	t.Run("HasOption returns true for existing key", func(t *testing.T) {
		ra, err := NewRouterAddress(5, time.Time{}, "NTCP2", map[string]string{"host": "127.0.0.1"})
		require.NoError(t, err)
		key, _ := data.ToI2PString("host")
		assert.True(t, ra.HasOption(key))
	})

	t.Run("CheckOption returns false for missing string key", func(t *testing.T) {
		ra, err := NewRouterAddress(5, time.Time{}, "NTCP2", map[string]string{"host": "127.0.0.1"})
		require.NoError(t, err)
		assert.False(t, ra.CheckOption("nonexistent"))
	})

	t.Run("CheckOption returns true for existing string key", func(t *testing.T) {
		ra, err := NewRouterAddress(5, time.Time{}, "NTCP2", map[string]string{"host": "127.0.0.1"})
		require.NoError(t, err)
		assert.True(t, ra.CheckOption("host"))
	})

	t.Run("GetOption on nil TransportOptions", func(t *testing.T) {
		ra := RouterAddress{TransportOptions: nil}
		key, _ := data.ToI2PString("host")
		result := ra.GetOption(key)
		assert.Nil(t, result)
	})
}

// =========================================================================
// Introducer out-of-range clamping Tests
// =========================================================================

func TestIntroducerOutOfRangeClamping(t *testing.T) {
	ra, err := NewRouterAddress(5, time.Time{}, "SSU2", map[string]string{
		"host": "127.0.0.1",
		"port": "9150",
		"ih0":  "hash0",
		"ih1":  "hash1",
		"ih2":  "hash2",
	})
	require.NoError(t, err)

	t.Run("negative number clamps to default (0)", func(t *testing.T) {
		result := ra.IntroducerHashString(-1)
		defaultResult := ra.IntroducerHashString(0)
		assert.Equal(t, defaultResult, result, "Negative introducer number should clamp to default")
	})

	t.Run("number above max clamps to default (0)", func(t *testing.T) {
		result := ra.IntroducerHashString(3)
		defaultResult := ra.IntroducerHashString(0)
		assert.Equal(t, defaultResult, result, "Above-max introducer number should clamp to default")
	})

	t.Run("valid numbers return correct values", func(t *testing.T) {
		for i := 0; i <= MAX_INTRODUCER_NUMBER; i++ {
			result := ra.IntroducerHashString(i)
			assert.NotNil(t, result, "Valid introducer number %d should return a value", i)
		}
	})

	t.Run("IntroducerExpirationString clamps out-of-range", func(t *testing.T) {
		result := ra.IntroducerExpirationString(-5)
		defaultResult := ra.IntroducerExpirationString(0)
		assert.Equal(t, defaultResult, result)
	})

	t.Run("IntroducerTagString clamps out-of-range", func(t *testing.T) {
		result := ra.IntroducerTagString(100)
		defaultResult := ra.IntroducerTagString(0)
		assert.Equal(t, defaultResult, result)
	})
}

// =========================================================================
// net.Addr interface Tests
// =========================================================================

func TestNetAddrInterfaceSatisfaction(t *testing.T) {
	ra, err := NewRouterAddress(5, time.Time{}, "NTCP2", map[string]string{
		"host": "127.0.0.1",
		"port": "9150",
	})
	require.NoError(t, err)

	var addr interface{} = ra
	_, ok := addr.(interface {
		Network() string
		String() string
	})
	assert.True(t, ok, "*RouterAddress should satisfy net.Addr interface")
}

func TestNetAddrInterface(t *testing.T) {
	ra, err := NewRouterAddress(5, time.Time{}, "NTCP2", map[string]string{
		"host": "192.168.1.1",
		"port": "9150",
	})
	require.NoError(t, err)

	var addr net.Addr = ra
	assert.NotEmpty(t, addr.Network())
	assert.NotEmpty(t, addr.String())
}

// =========================================================================
// Bytes() nil TransportType guard
// =========================================================================

func TestBytes_NilTransportType(t *testing.T) {
	t.Run("nil TransportType returns nil", func(t *testing.T) {
		cost, _ := data.NewIntegerFromInt(5, 1)
		dateBytes := make([]byte, data.DATE_SIZE)
		expDate, _, _ := data.NewDate(dateBytes)
		opts, _ := data.GoMapToMapping(map[string]string{})
		ra := RouterAddress{
			TransportCost:    cost,
			ExpirationDate:   expDate,
			TransportType:    nil,
			TransportOptions: opts,
		}
		assert.Nil(t, ra.Bytes(), "Bytes() should return nil when TransportType is nil")
	})

	t.Run("empty TransportType returns nil", func(t *testing.T) {
		cost, _ := data.NewIntegerFromInt(5, 1)
		dateBytes := make([]byte, data.DATE_SIZE)
		expDate, _, _ := data.NewDate(dateBytes)
		opts, _ := data.GoMapToMapping(map[string]string{})
		ra := RouterAddress{
			TransportCost:    cost,
			ExpirationDate:   expDate,
			TransportType:    data.I2PString{},
			TransportOptions: opts,
		}
		assert.Nil(t, ra.Bytes(), "Bytes() should return nil when TransportType is empty")
	})

	t.Run("valid TransportType produces non-nil bytes", func(t *testing.T) {
		ra, err := NewRouterAddress(5, time.Time{}, "NTCP2", map[string]string{"host": "127.0.0.1"})
		require.NoError(t, err)
		b := ra.Bytes()
		assert.NotNil(t, b, "Bytes() should produce non-nil output for valid address")
	})

	t.Run("nil TransportType cannot round-trip", func(t *testing.T) {
		cost, _ := data.NewIntegerFromInt(5, 1)
		dateBytes := make([]byte, data.DATE_SIZE)
		expDate, _, _ := data.NewDate(dateBytes)
		opts, _ := data.GoMapToMapping(map[string]string{})
		ra := RouterAddress{
			TransportCost:    cost,
			ExpirationDate:   expDate,
			TransportType:    nil,
			TransportOptions: opts,
		}
		serialized := ra.Bytes()
		assert.Nil(t, serialized, "Bytes() should return nil, not produce malformed data")
	})
}

// =========================================================================
// StaticKey() base64 decode
// =========================================================================

func TestStaticKey_Base64Decode(t *testing.T) {
	t.Run("base64-encoded 32-byte key", func(t *testing.T) {
		keyBytes := make([]byte, STATIC_KEY_SIZE)
		for i := range keyBytes {
			keyBytes[i] = byte(i)
		}
		encoded := i2pbase64.I2PEncoding.EncodeToString(keyBytes)
		require.Equal(t, 44, len(encoded), "base64 of 32 bytes should be 44 chars")

		ra, err := NewRouterAddress(5, time.Time{}, "NTCP2", map[string]string{
			"host": "127.0.0.1",
			"s":    encoded,
		})
		require.NoError(t, err)

		result, err := ra.StaticKey()
		assert.NoError(t, err, "StaticKey() should decode base64-encoded key")
		assert.Equal(t, keyBytes, result[:], "Decoded key should match original")
	})

	t.Run("raw 32-byte key still works", func(t *testing.T) {
		rawKey := strings.Repeat("A", STATIC_KEY_SIZE)
		ra, err := NewRouterAddress(5, time.Time{}, "NTCP2", map[string]string{
			"host": "127.0.0.1",
			"s":    rawKey,
		})
		require.NoError(t, err)

		result, err := ra.StaticKey()
		assert.NoError(t, err, "StaticKey() should accept raw 32-byte key")
		assert.Equal(t, []byte(rawKey), result[:])
	})

	t.Run("missing key returns error", func(t *testing.T) {
		ra, err := NewRouterAddress(5, time.Time{}, "NTCP2", map[string]string{
			"host": "127.0.0.1",
		})
		require.NoError(t, err)

		_, err = ra.StaticKey()
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrMissingStaticKey), "error should wrap ErrMissingStaticKey")
	})

	t.Run("wrong length returns error", func(t *testing.T) {
		ra, err := NewRouterAddress(5, time.Time{}, "NTCP2", map[string]string{
			"host": "127.0.0.1",
			"s":    "tooshort",
		})
		require.NoError(t, err)

		_, err = ra.StaticKey()
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrInvalidStaticKey), "error should wrap ErrInvalidStaticKey")
	})

	t.Run("standard base64 encoded key (non-I2P alphabet)", func(t *testing.T) {
		keyBytes := make([]byte, STATIC_KEY_SIZE)
		keyBytes[0] = 0xFF
		keyBytes[1] = 0xFE
		encoded := i2pbase64.I2PEncoding.EncodeToString(keyBytes)

		ra, err := NewRouterAddress(5, time.Time{}, "NTCP2", map[string]string{
			"host": "127.0.0.1",
			"s":    encoded,
		})
		require.NoError(t, err)

		result, err := ra.StaticKey()
		assert.NoError(t, err)
		assert.Equal(t, keyBytes, result[:])
	})
}

// =========================================================================
// InitializationVector() base64 decode
// =========================================================================

func TestInitializationVector_Base64Decode(t *testing.T) {
	t.Run("base64-encoded 16-byte IV", func(t *testing.T) {
		ivBytes := make([]byte, INITIALIZATION_VECTOR_SIZE)
		for i := range ivBytes {
			ivBytes[i] = byte(i + 0x10)
		}
		encoded := i2pbase64.I2PEncoding.EncodeToString(ivBytes)

		ra, err := NewRouterAddress(5, time.Time{}, "NTCP2", map[string]string{
			"host": "127.0.0.1",
			"i":    encoded,
		})
		require.NoError(t, err)

		result, err := ra.InitializationVector()
		assert.NoError(t, err, "InitializationVector() should decode base64-encoded IV")
		assert.Equal(t, ivBytes, result[:], "Decoded IV should match original")
	})

	t.Run("raw 16-byte IV still works", func(t *testing.T) {
		rawIV := strings.Repeat("B", INITIALIZATION_VECTOR_SIZE)
		ra, err := NewRouterAddress(5, time.Time{}, "NTCP2", map[string]string{
			"host": "127.0.0.1",
			"i":    rawIV,
		})
		require.NoError(t, err)

		result, err := ra.InitializationVector()
		assert.NoError(t, err, "InitializationVector() should accept raw 16-byte IV")
		assert.Equal(t, []byte(rawIV), result[:])
	})

	t.Run("missing IV returns error", func(t *testing.T) {
		ra, err := NewRouterAddress(5, time.Time{}, "NTCP2", map[string]string{
			"host": "127.0.0.1",
		})
		require.NoError(t, err)

		_, err = ra.InitializationVector()
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrMissingInitializationVector))
	})

	t.Run("wrong length returns error", func(t *testing.T) {
		ra, err := NewRouterAddress(5, time.Time{}, "NTCP2", map[string]string{
			"host": "127.0.0.1",
			"i":    "tooshort",
		})
		require.NoError(t, err)

		_, err = ra.InitializationVector()
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrInvalidInitializationVector))
	})
}

// =========================================================================
// ipVersionFromCaps() empty and unrecognized values
// =========================================================================

func TestIPVersionFromCaps_EmptyAndUnrecognized(t *testing.T) {
	t.Run("empty caps returns empty string", func(t *testing.T) {
		ra, err := NewRouterAddress(5, time.Time{}, "NTCP2", map[string]string{
			"caps": "",
		})
		require.NoError(t, err)
		assert.Equal(t, "", ra.ipVersionFromCaps(), "Empty caps should return empty string, not '4'")
	})

	t.Run("no caps option returns empty string", func(t *testing.T) {
		ra, err := NewRouterAddress(5, time.Time{}, "NTCP2", map[string]string{})
		require.NoError(t, err)
		assert.Equal(t, "", ra.ipVersionFromCaps())
	})

	t.Run("caps with 6 suffix returns IPv6", func(t *testing.T) {
		ra, err := NewRouterAddress(5, time.Time{}, "NTCP2", map[string]string{
			"caps": "BC6",
		})
		require.NoError(t, err)
		assert.Equal(t, IPV6_VERSION_STRING, ra.ipVersionFromCaps())
	})

	t.Run("caps without 6 suffix returns IPv4", func(t *testing.T) {
		ra, err := NewRouterAddress(5, time.Time{}, "NTCP2", map[string]string{
			"caps": "BC",
		})
		require.NoError(t, err)
		assert.Equal(t, IPV4_VERSION_STRING, ra.ipVersionFromCaps())
	})
}

// =========================================================================
// HasNonZeroExpiration()
// =========================================================================

func TestHasNonZeroExpiration(t *testing.T) {
	t.Run("all-zero expiration returns false", func(t *testing.T) {
		ra, err := NewRouterAddress(5, time.Time{}, "NTCP2", map[string]string{})
		require.NoError(t, err)
		assert.False(t, ra.HasNonZeroExpiration(), "Standard address should have zero expiration")
	})

	t.Run("non-zero expiration returns true", func(t *testing.T) {
		ra, err := NewRouterAddress(5, time.Time{}, "NTCP2", map[string]string{})
		require.NoError(t, err)
		ra.ExpirationDate[3] = 0x01
		assert.True(t, ra.HasNonZeroExpiration(), "Modified address should have non-zero expiration")
	})

	t.Run("nil expiration returns false", func(t *testing.T) {
		ra := &RouterAddress{}
		assert.False(t, ra.HasNonZeroExpiration())
	})
}

// =========================================================================
// Equals() asymmetric nil fields
// =========================================================================

func TestEquals_AsymmetricNilFields(t *testing.T) {
	t.Run("one nil bytes, one non-nil", func(t *testing.T) {
		ra1, err := NewRouterAddress(5, time.Time{}, "NTCP2", map[string]string{"host": "127.0.0.1"})
		require.NoError(t, err)

		ra2 := RouterAddress{}
		assert.Nil(t, ra2.Bytes())
		assert.NotNil(t, ra1.Bytes())
		assert.False(t, ra1.Equals(ra2), "Address with nil bytes should not equal valid address")
	})

	t.Run("both nil bytes are equal", func(t *testing.T) {
		ra1 := RouterAddress{}
		ra2 := RouterAddress{}
		assert.True(t, ra1.Equals(ra2), "Two addresses with nil bytes should be equal")
	})

	t.Run("same address is equal", func(t *testing.T) {
		ra, err := NewRouterAddress(5, time.Time{}, "NTCP2", map[string]string{"host": "127.0.0.1"})
		require.NoError(t, err)
		assert.True(t, ra.Equals(*ra))
	})
}

// =========================================================================
// StaticKey and InitializationVector successful roundtrip
// =========================================================================

func TestStaticKey_SuccessfulRoundtrip(t *testing.T) {
	keyBytes := make([]byte, STATIC_KEY_SIZE)
	for i := range keyBytes {
		keyBytes[i] = byte(i * 3)
	}
	encoded := i2pbase64.I2PEncoding.EncodeToString(keyBytes)

	ra, err := NewRouterAddress(5, time.Time{}, "NTCP2", map[string]string{
		"host": "127.0.0.1",
		"s":    encoded,
	})
	require.NoError(t, err)

	result, err := ra.StaticKey()
	assert.NoError(t, err)

	for i := 0; i < STATIC_KEY_SIZE; i++ {
		assert.Equal(t, keyBytes[i], result[i], "Byte %d mismatch", i)
	}
}

func TestInitializationVector_SuccessfulRoundtrip(t *testing.T) {
	ivBytes := make([]byte, INITIALIZATION_VECTOR_SIZE)
	for i := range ivBytes {
		ivBytes[i] = byte(i * 7)
	}
	encoded := i2pbase64.I2PEncoding.EncodeToString(ivBytes)

	ra, err := NewRouterAddress(5, time.Time{}, "NTCP2", map[string]string{
		"host": "127.0.0.1",
		"i":    encoded,
	})
	require.NoError(t, err)

	result, err := ra.InitializationVector()
	assert.NoError(t, err)

	for i := 0; i < INITIALIZATION_VECTOR_SIZE; i++ {
		assert.Equal(t, ivBytes[i], result[i], "Byte %d mismatch", i)
	}
}

// =========================================================================
// StaticKey with I2P base64 from Java router format
// =========================================================================

func TestStaticKey_JavaRouterFormat(t *testing.T) {
	keyBytes := make([]byte, 32)
	for i := range keyBytes {
		keyBytes[i] = byte(0xAA ^ byte(i))
	}

	i2pEncoded := i2pbase64.I2PEncoding.EncodeToString(keyBytes)
	stdEncoded := base64.StdEncoding.EncodeToString(keyBytes)

	t.Logf("I2P encoded: %s", i2pEncoded)
	t.Logf("Std encoded: %s", stdEncoded)

	ra, err := NewRouterAddress(5, time.Time{}, "NTCP2", map[string]string{
		"host": "127.0.0.1",
		"s":    i2pEncoded,
	})
	require.NoError(t, err)

	result, err := ra.StaticKey()
	assert.NoError(t, err, "StaticKey() should handle I2P base64-encoded key")
	assert.Equal(t, keyBytes, result[:], "Decoded key should match original bytes")
}
