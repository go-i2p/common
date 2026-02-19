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
