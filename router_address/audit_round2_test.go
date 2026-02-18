package router_address

import (
	"net"
	"testing"
	"time"

	"github.com/go-i2p/common/data"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// [BUG] String() panics when TransportOptions is nil / zero-value RouterAddress
// =============================================================================

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

// =============================================================================
// [SPEC] IPVersion() detection from host address instead of caps suffix
// =============================================================================

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
		// IPv6 host but IPv4 caps — host should win
		ra, err := NewRouterAddress(5, time.Time{}, "NTCP2", map[string]string{
			"host": "::1",
			"caps": "BC",
		})
		require.NoError(t, err)
		assert.Equal(t, IPV6_VERSION_STRING, ra.IPVersion())
	})
}

// =============================================================================
// [BUG] Network() appends empty string when IPVersion() fails
// =============================================================================

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

// =============================================================================
// [GAP] ReadRouterAddress does not reject non-zero expiration
// =============================================================================

func TestReadRouterAddressNonZeroExpiration(t *testing.T) {
	t.Run("non-zero expiration parsed with warning but not rejected", func(t *testing.T) {
		// Build data: cost=5, non-zero expiration, empty transport, empty mapping
		buf := []byte{0x05}
		// Non-zero expiration
		buf = append(buf, 0x00, 0x00, 0x01, 0x8F, 0x5C, 0xE4, 0x00, 0x00)
		buf = append(buf, 0x00)       // empty transport string
		buf = append(buf, 0x00, 0x00) // empty mapping

		ra, _, err := ReadRouterAddress(buf)
		// Per current implementation: warning is logged but no error returned (lenient parsing)
		assert.NoError(t, err, "ReadRouterAddress should accept non-zero expiration with warning")
		assert.Equal(t, 5, ra.Cost())
		// Verify the expiration bytes were preserved
		exp := ra.Expiration()
		assert.False(t, isAllZeros(exp[:]), "Non-zero expiration should be preserved")
	})

	t.Run("zero expiration accepted cleanly", func(t *testing.T) {
		buf := []byte{0x05}
		buf = append(buf, make([]byte, 8)...) // all zeros
		buf = append(buf, 0x00)               // empty transport
		buf = append(buf, 0x00, 0x00)         // empty mapping

		ra, _, err := ReadRouterAddress(buf)
		assert.NoError(t, err)
		exp := ra.Expiration()
		assert.True(t, isAllZeros(exp[:]), "Zero expiration should be all zeros")
	})
}

// =============================================================================
// [GAP] Bytes() does not validate TransportType is well-formed I2PString
// =============================================================================

func TestBytesTransportTypeValidation(t *testing.T) {
	t.Run("well-formed I2PString in Bytes", func(t *testing.T) {
		ra, err := NewRouterAddress(5, time.Time{}, "NTCP2", map[string]string{"host": "127.0.0.1"})
		require.NoError(t, err)
		serialized := ra.Bytes()
		require.NotNil(t, serialized)

		// Verify round-trip
		parsed, _, err := ReadRouterAddress(serialized)
		assert.NoError(t, err)
		style, _ := parsed.TransportStyle().Data()
		assert.Equal(t, "NTCP2", style)
	})

	t.Run("manually constructed TransportType without length prefix in Bytes", func(t *testing.T) {
		cost, _ := data.NewIntegerFromInt(5, 1)
		expDate, _, _ := data.NewDate(make([]byte, data.DATE_SIZE))
		mapping, _ := data.GoMapToMapping(map[string]string{})

		// Manually set TransportType without length prefix — this is invalid
		ra := &RouterAddress{
			TransportCost:    cost,
			ExpirationDate:   expDate,
			TransportType:    data.I2PString("NTCP2"), // no length prefix
			TransportOptions: mapping,
		}
		// Bytes() will include it but it will be malformed
		serialized := ra.Bytes()
		assert.NotNil(t, serialized, "Bytes() should still produce output")
	})
}

// =============================================================================
// [GAP] Host() rejects hostnames — documented deviation from spec
// =============================================================================

func TestHostRejectsHostnames(t *testing.T) {
	t.Run("hostname rejected", func(t *testing.T) {
		ra, err := NewRouterAddress(5, time.Time{}, "NTCP2", map[string]string{
			"host": "example.com",
		})
		require.NoError(t, err)
		_, err = ra.Host()
		assert.Error(t, err, "Host() should reject hostnames")
		assert.Contains(t, err.Error(), "invalid IP address")
	})

	t.Run("IP address accepted", func(t *testing.T) {
		ra, err := NewRouterAddress(5, time.Time{}, "NTCP2", map[string]string{
			"host": "192.168.1.1",
		})
		require.NoError(t, err)
		host, err := ra.Host()
		assert.NoError(t, err)
		assert.NotNil(t, host)
	})
}

// =============================================================================
// [GAP] Equals() method for comparing two RouterAddress instances
// =============================================================================

func TestRouterAddressEquals(t *testing.T) {
	t.Run("equal addresses", func(t *testing.T) {
		ra1, err := NewRouterAddress(5, time.Time{}, "NTCP2", map[string]string{"host": "127.0.0.1", "port": "9150"})
		require.NoError(t, err)
		ra2, err := NewRouterAddress(5, time.Time{}, "NTCP2", map[string]string{"host": "127.0.0.1", "port": "9150"})
		require.NoError(t, err)

		assert.True(t, ra1.Equals(*ra2), "Identical addresses should be equal")
	})

	t.Run("different cost", func(t *testing.T) {
		ra1, err := NewRouterAddress(5, time.Time{}, "NTCP2", map[string]string{"host": "127.0.0.1"})
		require.NoError(t, err)
		ra2, err := NewRouterAddress(10, time.Time{}, "NTCP2", map[string]string{"host": "127.0.0.1"})
		require.NoError(t, err)

		assert.False(t, ra1.Equals(*ra2), "Different cost should not be equal")
	})

	t.Run("different transport type", func(t *testing.T) {
		ra1, err := NewRouterAddress(5, time.Time{}, "NTCP2", map[string]string{"host": "127.0.0.1"})
		require.NoError(t, err)
		ra2, err := NewRouterAddress(5, time.Time{}, "SSU2", map[string]string{"host": "127.0.0.1"})
		require.NoError(t, err)

		assert.False(t, ra1.Equals(*ra2), "Different transport type should not be equal")
	})

	t.Run("different host", func(t *testing.T) {
		ra1, err := NewRouterAddress(5, time.Time{}, "NTCP2", map[string]string{"host": "127.0.0.1"})
		require.NoError(t, err)
		ra2, err := NewRouterAddress(5, time.Time{}, "NTCP2", map[string]string{"host": "10.0.0.1"})
		require.NoError(t, err)

		assert.False(t, ra1.Equals(*ra2), "Different host should not be equal")
	})

	t.Run("nil bytes addresses both nil", func(t *testing.T) {
		ra1 := RouterAddress{}
		ra2 := RouterAddress{}
		assert.True(t, ra1.Equals(ra2), "Both nil-bytes addresses should be equal")
	})
}

// =============================================================================
// [GAP] MAX_INTRODUCER_NUMBER documentation
// =============================================================================

func TestMaxIntroducerNumber(t *testing.T) {
	assert.Equal(t, 2, MAX_INTRODUCER_NUMBER, "MAX_INTRODUCER_NUMBER should be 2 per SSU2 spec")
	assert.Equal(t, 0, MIN_INTRODUCER_NUMBER)
	assert.Equal(t, 0, DEFAULT_INTRODUCER_NUMBER)
}

// =============================================================================
// [TEST] ReadRouterAddress with non-zero expiration field
// =============================================================================

func TestReadRouterAddressExpirationWarning(t *testing.T) {
	// Build minimal valid data with non-zero expiration
	buf := []byte{0x0A} // cost=10
	// Expiration: 0x0000018F5CE40000 (some timestamp)
	buf = append(buf, 0x00, 0x00, 0x01, 0x8F, 0x5C, 0xE4, 0x00, 0x00)
	transportStr, _ := data.ToI2PString("NTCP2")
	buf = append(buf, transportStr...)
	mapping, _ := data.GoMapToMapping(map[string]string{})
	buf = append(buf, mapping.Data()...)

	ra, _, err := ReadRouterAddress(buf)
	// Should parse successfully (lenient)
	assert.NoError(t, err)
	assert.Equal(t, 10, ra.Cost())

	// Verify the non-zero expiration is preserved
	exp := ra.Expiration()
	assert.False(t, isAllZeros(exp[:]))
}

// =============================================================================
// [TEST] FuzzReadRouterAddress
// =============================================================================

func FuzzReadRouterAddress(f *testing.F) {
	// Seed corpus
	f.Add([]byte{}) // empty
	f.Add([]byte{0x05})
	f.Add(make([]byte, 12)) // minimum size, all zeros

	// Valid: cost=5, zero expiration, empty transport, empty mapping
	valid := []byte{0x05}
	valid = append(valid, make([]byte, 8)...)
	valid = append(valid, 0x00)
	valid = append(valid, 0x00, 0x00)
	f.Add(valid)

	// With transport and options
	withOpts := []byte{0x05}
	withOpts = append(withOpts, make([]byte, 8)...)
	ts, _ := data.ToI2PString("NTCP2")
	withOpts = append(withOpts, ts...)
	m, _ := data.GoMapToMapping(map[string]string{"host": "127.0.0.1"})
	withOpts = append(withOpts, m.Data()...)
	f.Add(withOpts)

	f.Fuzz(func(t *testing.T, input []byte) {
		// Must not panic
		ra, remainder, err := ReadRouterAddress(input)
		if err == nil {
			// If parse succeeded, basic properties should not panic
			_ = ra.Cost()
			_ = ra.Expiration()
			_ = ra.TransportStyle()
			_ = ra.Options()
			_ = ra.Bytes()
		}
		_ = remainder
	})
}

// =============================================================================
// [TEST] Bytes() round-trip with unusual transport styles
// =============================================================================

func TestBytesRoundTripUnusualTransports(t *testing.T) {
	t.Run("single character transport", func(t *testing.T) {
		ra, err := NewRouterAddress(1, time.Time{}, "X", map[string]string{"host": "10.0.0.1"})
		require.NoError(t, err)
		serialized := ra.Bytes()
		require.NotNil(t, serialized)

		parsed, _, err := ReadRouterAddress(serialized)
		assert.NoError(t, err)
		style, _ := parsed.TransportStyle().Data()
		assert.Equal(t, "X", style)
	})

	t.Run("long transport name", func(t *testing.T) {
		// 50 character transport name
		longName := "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmn"
		ra, err := NewRouterAddress(1, time.Time{}, longName, map[string]string{"host": "10.0.0.1"})
		require.NoError(t, err)
		serialized := ra.Bytes()
		require.NotNil(t, serialized)

		parsed, _, err := ReadRouterAddress(serialized)
		assert.NoError(t, err)
		style, _ := parsed.TransportStyle().Data()
		assert.Equal(t, longName, style)
	})

	t.Run("UTF-8 transport name", func(t *testing.T) {
		ra, err := NewRouterAddress(1, time.Time{}, "NTCP2-日本語", map[string]string{"host": "10.0.0.1"})
		require.NoError(t, err)
		serialized := ra.Bytes()
		require.NotNil(t, serialized)

		parsed, _, err := ReadRouterAddress(serialized)
		assert.NoError(t, err)
		style, _ := parsed.TransportStyle().Data()
		assert.Equal(t, "NTCP2-日本語", style)
	})
}

// =============================================================================
// [TEST] GetOption(), HasOption(), CheckOption() with missing or empty mapping
// =============================================================================

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

// =============================================================================
// [TEST] IntroducerHashString/ExpirationString/TagString out-of-range clamping
// =============================================================================

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
		// Out of range → uses DEFAULT_INTRODUCER_NUMBER (0) → looks up "ih0"
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

// =============================================================================
// [TEST] Concurrent reads on RouterAddress (documenting thread safety)
// =============================================================================

func TestConcurrentReads(t *testing.T) {
	ra, err := NewRouterAddress(5, time.Time{}, "NTCP2", map[string]string{
		"host": "192.168.1.1",
		"port": "9150",
		"v":    "2",
	})
	require.NoError(t, err)

	// Multiple goroutines reading concurrently should not race
	done := make(chan struct{})
	for i := 0; i < 10; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			for j := 0; j < 100; j++ {
				_ = ra.Cost()
				_ = ra.Expiration()
				_ = ra.TransportStyle()
				_ = ra.Options()
				_ = ra.Network()
				_ = ra.IPVersion()
				_ = ra.String()
				_ = ra.Bytes()
				_ = ra.HasValidHost()
				_ = ra.HasValidPort()
			}
		}()
	}
	for i := 0; i < 10; i++ {
		<-done
	}
}

// =============================================================================
// [QUALITY] createExpirationDate ignores parameter
// =============================================================================

func TestCreateExpirationDateIgnoresParameter(t *testing.T) {
	farFuture := time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)
	ra, err := NewRouterAddress(5, farFuture, "NTCP2", map[string]string{"host": "127.0.0.1"})
	require.NoError(t, err)

	exp := ra.Expiration()
	assert.True(t, isAllZeros(exp[:]), "Expiration must be all zeros regardless of input time")
}

// =============================================================================
// [QUALITY] checkValid() return signature
// =============================================================================

func TestCheckValidSignature(t *testing.T) {
	// checkValid returns (error, bool) — acknowledged as legacy API
	ra, err := NewRouterAddress(5, time.Time{}, "NTCP2", map[string]string{"host": "127.0.0.1"})
	require.NoError(t, err)

	e, exit := ra.checkValid()
	assert.NoError(t, e)
	assert.False(t, exit)
}

// =============================================================================
// [QUALITY] Mixed pointer and value receivers
// =============================================================================

func TestReceiverConsistencyCompilation(t *testing.T) {
	// Verify that both pointer and value contexts work correctly
	ra, err := NewRouterAddress(5, time.Time{}, "NTCP2", map[string]string{
		"host": "192.168.1.1",
		"port": "9150",
	})
	require.NoError(t, err)

	// Pointer receiver methods (via *RouterAddress)
	_ = ra.Network()
	_ = ra.IPVersion()
	_ = ra.UDP()
	_ = ra.String()

	// Value receiver methods (via RouterAddress value)
	val := *ra
	_ = val.Cost()
	_ = val.Expiration()
	_ = val.Bytes()
	_ = val.TransportStyle()
	_ = val.Options()
	_ = val.HasValidHost()
	_ = val.HasValidPort()
	_, _ = val.Host()
	_, _ = val.Port()
}

// =============================================================================
// [QUALITY] Verbose debug logging in hot-path methods
// =============================================================================

func BenchmarkRouterAddressCost(b *testing.B) {
	ra, _ := NewRouterAddress(5, time.Time{}, "NTCP2", map[string]string{"host": "127.0.0.1"})
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ra.Cost()
	}
}

func BenchmarkRouterAddressNetwork(b *testing.B) {
	ra, _ := NewRouterAddress(5, time.Time{}, "NTCP2", map[string]string{"host": "127.0.0.1"})
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ra.Network()
	}
}

func BenchmarkRouterAddressBytes(b *testing.B) {
	ra, _ := NewRouterAddress(5, time.Time{}, "NTCP2", map[string]string{
		"host": "192.168.1.1",
		"port": "9150",
	})
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ra.Bytes()
	}
}

func BenchmarkReadRouterAddress(b *testing.B) {
	ra, _ := NewRouterAddress(5, time.Time{}, "NTCP2", map[string]string{
		"host": "192.168.1.1",
		"port": "9150",
	})
	serialized := ra.Bytes()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = ReadRouterAddress(serialized)
	}
}

// =============================================================================
// net.Addr interface verification
// =============================================================================

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
