package data

import (
	"encoding/binary"
	"math"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTimeFromMilliseconds(t *testing.T) {
	assert := assert.New(t)

	next_day := Date{0x00, 0x00, 0x00, 0x00, 0x05, 0x26, 0x5c, 0x00}
	go_time := next_day.Time()

	assert.Equal(int64(86400), go_time.Unix(), "Date.Time() did not parse time in milliseconds")
}

// TestNewDateFromUnix tests the NewDateFromUnix constructor with validation.
func TestNewDateFromUnix(t *testing.T) {
	t.Run("valid timestamp - zero", func(t *testing.T) {
		date, err := NewDateFromUnix(0)
		require.NoError(t, err)
		require.NotNil(t, date)
		assert.True(t, date.IsZero())
		assert.Equal(t, int64(0), date.Time().Unix())
	})

	t.Run("valid timestamp - positive", func(t *testing.T) {
		timestamp := int64(1234567890) // Feb 13, 2009
		date, err := NewDateFromUnix(timestamp)
		require.NoError(t, err)
		require.NotNil(t, date)
		assert.False(t, date.IsZero())
		assert.Equal(t, timestamp, date.Time().Unix())
	})

	t.Run("valid timestamp - current time", func(t *testing.T) {
		now := time.Now().Unix()
		date, err := NewDateFromUnix(now)
		require.NoError(t, err)
		require.NotNil(t, date)
		assert.False(t, date.IsZero())
		// Allow small time difference due to conversion
		assert.InDelta(t, now, date.Time().Unix(), 1)
	})

	t.Run("negative timestamp", func(t *testing.T) {
		date, err := NewDateFromUnix(-1)
		require.Error(t, err)
		assert.Nil(t, date)
		assert.Contains(t, err.Error(), "timestamp cannot be negative")
	})

	t.Run("large negative timestamp", func(t *testing.T) {
		date, err := NewDateFromUnix(-1000000)
		require.Error(t, err)
		assert.Nil(t, date)
		assert.Contains(t, err.Error(), "timestamp cannot be negative")
	})

	t.Run("maximum safe timestamp", func(t *testing.T) {
		maxTimestamp := int64(math.MaxInt64 / 1000)
		date, err := NewDateFromUnix(maxTimestamp)
		require.NoError(t, err)
		require.NotNil(t, date)
		assert.False(t, date.IsZero())
	})

	t.Run("timestamp exceeds maximum", func(t *testing.T) {
		tooLarge := int64(math.MaxInt64/1000) + 1
		date, err := NewDateFromUnix(tooLarge)
		require.Error(t, err)
		assert.Nil(t, date)
		assert.Contains(t, err.Error(), "timestamp too large")
	})

	t.Run("round trip with DateFromTime", func(t *testing.T) {
		originalTime := time.Unix(1700000000, 0) // Nov 14, 2023
		date1, err := DateFromTime(originalTime)
		require.NoError(t, err)

		date2, err := NewDateFromUnix(originalTime.Unix())
		require.NoError(t, err)

		// Both should produce the same date
		assert.Equal(t, date1.Bytes(), date2.Bytes())
	})
}

// TestNewDateFromMillis tests the NewDateFromMillis constructor.
func TestNewDateFromMillis(t *testing.T) {
	t.Run("valid milliseconds - zero", func(t *testing.T) {
		date, err := NewDateFromMillis(0)
		require.NoError(t, err)
		require.NotNil(t, date)
		assert.True(t, date.IsZero())
	})

	t.Run("valid milliseconds - one second", func(t *testing.T) {
		date, err := NewDateFromMillis(1000)
		require.NoError(t, err)
		require.NotNil(t, date)
		assert.False(t, date.IsZero())
		assert.Equal(t, int64(1), date.Time().Unix())
	})

	t.Run("valid milliseconds - with fractional seconds", func(t *testing.T) {
		millis := int64(1234567890123) // Includes milliseconds
		date, err := NewDateFromMillis(millis)
		require.NoError(t, err)
		require.NotNil(t, date)
		assert.False(t, date.IsZero())

		// Verify milliseconds are preserved
		expectedSeconds := millis / 1000
		assert.Equal(t, expectedSeconds, date.Time().Unix())
	})

	t.Run("negative milliseconds", func(t *testing.T) {
		date, err := NewDateFromMillis(-1)
		require.Error(t, err)
		assert.Nil(t, date)
		assert.Contains(t, err.Error(), "milliseconds cannot be negative")
	})

	t.Run("large negative milliseconds", func(t *testing.T) {
		date, err := NewDateFromMillis(-1000000000)
		require.Error(t, err)
		assert.Nil(t, date)
		assert.Contains(t, err.Error(), "milliseconds cannot be negative")
	})

	t.Run("large positive milliseconds", func(t *testing.T) {
		largeMillis := int64(1000000000000) // Year 2001
		date, err := NewDateFromMillis(largeMillis)
		require.NoError(t, err)
		require.NotNil(t, date)
		assert.False(t, date.IsZero())
	})

	t.Run("round trip - seconds to millis", func(t *testing.T) {
		timestamp := int64(1234567890)
		millis := timestamp * 1000

		date1, err := NewDateFromUnix(timestamp)
		require.NoError(t, err)

		date2, err := NewDateFromMillis(millis)
		require.NoError(t, err)

		// Should be equal (within millisecond precision)
		assert.Equal(t, date1.Time().Unix(), date2.Time().Unix())
	})

	t.Run("millisecond precision", func(t *testing.T) {
		millis := int64(1234567890500) // .5 seconds
		date, err := NewDateFromMillis(millis)
		require.NoError(t, err)

		// Convert back and check
		recoveredTime := date.Time()
		recoveredMillis := recoveredTime.UnixNano() / 1000000

		// Should preserve milliseconds
		assert.InDelta(t, millis, recoveredMillis, 1)
	})
}

// TestDateTimeNoOverflow verifies that Date.Time() uses time.UnixMilli
// instead of the overflow-prone multiplication (seconds.Int()*1000000).
func TestDateTimeNoOverflow(t *testing.T) {
	t.Run("large date near overflow boundary", func(t *testing.T) {
		millis := int64(9223372036854) // Near the old overflow boundary
		var date Date
		binary.BigEndian.PutUint64(date[:], uint64(millis))

		result := date.Time()
		assert.True(t, result.After(time.Date(2200, 1, 1, 0, 0, 0, 0, time.UTC)),
			"Date near overflow boundary should be far future, got %v", result)
	})

	t.Run("known date roundtrip", func(t *testing.T) {
		next_day := Date{0x00, 0x00, 0x00, 0x00, 0x05, 0x26, 0x5c, 0x00}
		result := next_day.Time()
		assert.Equal(t, int64(86400), result.Unix(),
			"Date.Time() should correctly parse milliseconds")
	})

	t.Run("zero date", func(t *testing.T) {
		var date Date
		result := date.Time()
		assert.True(t, result.Equal(time.UnixMilli(0)),
			"Zero date should produce Unix epoch")
	})

	t.Run("current era date", func(t *testing.T) {
		millis := int64(1771372800000) // ~2026-02-18
		var date Date
		binary.BigEndian.PutUint64(date[:], uint64(millis))

		result := date.Time()
		assert.True(t, result.Year() >= 2026, "Should parse to year 2026+")
	})
}

// BenchmarkNewDateFromUnix benchmarks the NewDateFromUnix constructor.
func BenchmarkNewDateFromUnix(b *testing.B) {
	timestamp := int64(1234567890)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = NewDateFromUnix(timestamp)
	}
}

// BenchmarkNewDateFromMillis benchmarks the NewDateFromMillis constructor.
func BenchmarkNewDateFromMillis(b *testing.B) {
	millis := int64(1234567890000)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = NewDateFromMillis(millis)
	}
}

// BenchmarkDateIsZero benchmarks the IsZero method.
func BenchmarkDateIsZero(b *testing.B) {
	date, _ := NewDateFromUnix(1234567890)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = date.IsZero()
	}
}

// BenchmarkDateFromTime benchmarks the DateFromTime function.
func BenchmarkDateFromTime(b *testing.B) {
	t := time.Now()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = DateFromTime(t)
	}
}

// TestDateFromTimePreEpoch verifies that DateFromTime rejects pre-epoch times.
func TestDateFromTimePreEpoch(t *testing.T) {
	t.Run("one second before epoch", func(t *testing.T) {
		preEpoch := time.Unix(-1, 0)
		date, err := DateFromTime(preEpoch)
		require.Error(t, err, "should reject pre-epoch time")
		assert.Nil(t, date)
		assert.Contains(t, err.Error(), "before Unix epoch")
	})

	t.Run("far past date", func(t *testing.T) {
		farPast := time.Date(1969, 12, 31, 23, 59, 59, 0, time.UTC)
		date, err := DateFromTime(farPast)
		require.Error(t, err, "should reject date before 1970")
		assert.Nil(t, date)
		assert.Contains(t, err.Error(), "before Unix epoch")
	})

	t.Run("one nanosecond before epoch", func(t *testing.T) {
		almostEpoch := time.Unix(0, -1)
		date, err := DateFromTime(almostEpoch)
		require.Error(t, err, "should reject time even 1ns before epoch")
		assert.Nil(t, date)
	})

	t.Run("exactly at epoch succeeds", func(t *testing.T) {
		epoch := time.Unix(0, 0)
		date, err := DateFromTime(epoch)
		require.NoError(t, err, "epoch itself should be accepted")
		require.NotNil(t, date)
		assert.True(t, date.IsZero())
	})

	t.Run("one millisecond after epoch succeeds", func(t *testing.T) {
		afterEpoch := time.UnixMilli(1)
		date, err := DateFromTime(afterEpoch)
		require.NoError(t, err)
		require.NotNil(t, date)
		assert.False(t, date.IsZero())
	})
}

// TestDateFromTimeUsesUnixMilli verifies that DateFromTime uses UnixMilli
// and does not overflow for dates beyond year 2262.
func TestDateFromTimeUsesUnixMilli(t *testing.T) {
	t.Run("year 3000 does not overflow", func(t *testing.T) {
		future := time.Date(3000, 1, 1, 0, 0, 0, 0, time.UTC)
		date, err := DateFromTime(future)
		require.NoError(t, err)
		require.NotNil(t, date)

		recovered := date.Time()
		diff := future.Sub(recovered).Abs()
		assert.Less(t, diff, 2*time.Second,
			"Year 3000 should survive round-trip without overflow, got %v", recovered)
		assert.True(t, recovered.Year() >= 2999,
			"Recovered year should be 2999 or 3000, got %d", recovered.Year())
	})

	t.Run("year 2262 boundary does not overflow", func(t *testing.T) {
		// This date is near the int64 nanosecond overflow boundary (~April 2262)
		boundary := time.Date(2262, 4, 12, 0, 0, 0, 0, time.UTC)
		date, err := DateFromTime(boundary)
		require.NoError(t, err)
		require.NotNil(t, date)

		recovered := date.Time()
		assert.Equal(t, 2262, recovered.Year())
	})

	t.Run("current time round-trips correctly", func(t *testing.T) {
		now := time.Now().Truncate(time.Millisecond) // Date has ms precision
		date, err := DateFromTime(now)
		require.NoError(t, err)

		recovered := date.Time()
		diff := now.Sub(recovered).Abs()
		assert.Less(t, diff, time.Millisecond,
			"Current time should round-trip within 1ms")
	})
}

// TestDateTimeUnsignedDecoding verifies that Date.Time() uses unsigned decoding
// to handle the full range of I2P Date values.
func TestDateTimeUnsignedDecoding(t *testing.T) {
	t.Run("value above signed int64 range returns zero time", func(t *testing.T) {
		// Set high bit: this is > 2^63 milliseconds
		var date Date
		date[0] = 0x80
		result := date.Time()
		// Should return zero time since the unsigned value exceeds math.MaxInt64
		assert.True(t, result.IsZero(),
			"Date with high bit set should return zero time, got %v", result)
	})

	t.Run("max uint64 value returns zero time", func(t *testing.T) {
		date := Date{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
		result := date.Time()
		// Should return zero time since the unsigned value exceeds math.MaxInt64
		assert.True(t, result.IsZero(),
			"Max date should return zero time, got %v", result)
	})

	t.Run("normal values still work", func(t *testing.T) {
		next_day := Date{0x00, 0x00, 0x00, 0x00, 0x05, 0x26, 0x5c, 0x00}
		result := next_day.Time()
		assert.Equal(t, int64(86400), result.Unix())
	})
}

// TestDateIntOverflow documents and locks in Date.Int() silent-zero behaviour for
// values whose unsigned millisecond count exceeds math.MaxInt64.
// Callers should use Date.Time() instead of Date.Int() for reliable full-range handling.
func TestDateIntOverflow(t *testing.T) {
	t.Run("high bit set returns 0 from Int()", func(t *testing.T) {
		// 0x80_00_00_00_00_00_00_00 == 2^63, which overflows signed int64.
		// Date.Int() silently returns 0 for this case; Date.Time() is the safe alternative.
		var date Date
		date[0] = 0x80
		result := date.Int()
		assert.Equal(t, 0, result,
			"Date.Int() must return 0 for values >= 2^63 (overflow footgun - use Date.Time())")
	})

	t.Run("max uint64 returns 0 from Int()", func(t *testing.T) {
		date := Date{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
		result := date.Int()
		assert.Equal(t, 0, result,
			"Date.Int() must return 0 for max uint64 (overflow footgun - use Date.Time())")
	})

	t.Run("value below 2^63 returns correct integer", func(t *testing.T) {
		// 86400000 ms = 1 day. Encoding: 0x00 0x00 0x00 0x00 0x05 0x26 0x5C 0x00
		date := Date{0x00, 0x00, 0x00, 0x00, 0x05, 0x26, 0x5c, 0x00}
		result := date.Int()
		assert.Equal(t, 86400000, result,
			"Date.Int() should return correct value for unsigned values below 2^63")
	})

	t.Run("Int() zero is ambiguous: could be overflow or valid zero date", func(t *testing.T) {
		zeroDate := Date{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
		overflowDate := Date{0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
		// Both return 0 — callers cannot distinguish them; use Date.Time() instead.
		assert.Equal(t, 0, zeroDate.Int())
		assert.Equal(t, 0, overflowDate.Int())
	})
}

// TestDateTimeHighBitReturnsZeroTime verifies that Date.Time() returns zero time
// for dates with the high bit set (unsigned value > math.MaxInt64), instead of
// silently saturating to math.MaxInt64 (GAP-2 fix).
func TestDateTimeHighBitReturnsZeroTime(t *testing.T) {
	// Date with high bit set: 0x80 0x00 ... 0x00 => unsigned value = 2^63
	highBitDate := Date{0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	result := highBitDate.Time()
	assert.True(t, result.IsZero(),
		"Date.Time() should return zero time for dates exceeding math.MaxInt64")

	// All-FF date: max unsigned value
	allFFDate := Date{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	result2 := allFFDate.Time()
	assert.True(t, result2.IsZero(),
		"Date.Time() should return zero time for max unsigned date")

	// Normal date should still work
	normalDate := Date{0x00, 0x00, 0x00, 0x00, 0x05, 0x26, 0x5c, 0x00}
	result3 := normalDate.Time()
	assert.False(t, result3.IsZero(), "Normal date should not return zero time")
	assert.Equal(t, int64(86400), result3.Unix(), "Normal date should parse correctly")
}
