package router_address

import (
	"bytes"
	"testing"
	"time"

	"github.com/go-i2p/common/data"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =========================================================================
// Round-trip serialization Tests
// =========================================================================

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

	extra := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	dataWithRemainder := append(serialized, extra...)

	_, remainder, err := ReadRouterAddress(dataWithRemainder)
	assert.NoError(t, err)
	assert.Equal(t, extra, remainder, "Remainder should be the appended bytes")
}

// =========================================================================
// Bytes() round-trip with unusual transport styles
// =========================================================================

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

// =========================================================================
// TransportType validation in Bytes()
// =========================================================================

func TestBytesTransportTypeValidation(t *testing.T) {
	t.Run("well-formed I2PString in Bytes", func(t *testing.T) {
		ra, err := NewRouterAddress(5, time.Time{}, "NTCP2", map[string]string{"host": "127.0.0.1"})
		require.NoError(t, err)
		serialized := ra.Bytes()
		require.NotNil(t, serialized)

		parsed, _, err := ReadRouterAddress(serialized)
		assert.NoError(t, err)
		style, _ := parsed.TransportStyle().Data()
		assert.Equal(t, "NTCP2", style)
	})

	t.Run("manually constructed TransportType without length prefix in Bytes", func(t *testing.T) {
		cost, _ := data.NewIntegerFromInt(5, 1)
		expDate, _, _ := data.NewDate(make([]byte, data.DATE_SIZE))
		mapping, _ := data.GoMapToMapping(map[string]string{})

		ra := &RouterAddress{
			TransportCost:    cost,
			ExpirationDate:   expDate,
			TransportType:    data.I2PString("NTCP2"),
			TransportOptions: mapping,
		}
		serialized := ra.Bytes()
		assert.NotNil(t, serialized, "Bytes() should still produce output")
	})
}

// =========================================================================
// Equals() Tests
// =========================================================================

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

// =========================================================================
// Concurrent reads Tests
// =========================================================================

func TestConcurrentReads(t *testing.T) {
	ra, err := NewRouterAddress(5, time.Time{}, "NTCP2", map[string]string{
		"host": "192.168.1.1",
		"port": "9150",
		"v":    "2",
	})
	require.NoError(t, err)

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

// =========================================================================
// Receiver consistency compilation
// =========================================================================

func TestReceiverConsistencyCompilation(t *testing.T) {
	ra, err := NewRouterAddress(5, time.Time{}, "NTCP2", map[string]string{
		"host": "192.168.1.1",
		"port": "9150",
	})
	require.NoError(t, err)

	_ = ra.Network()
	_ = ra.IPVersion()
	_ = ra.UDP()
	_ = ra.String()

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

// =========================================================================
// Benchmarks
// =========================================================================

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
