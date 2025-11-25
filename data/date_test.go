package data

import (
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

// TestDateIsZero tests the IsZero method.
func TestDateIsZero(t *testing.T) {
	t.Run("zero date - all zeros", func(t *testing.T) {
		var date Date
		assert.True(t, date.IsZero())
	})

	t.Run("zero date - explicitly created", func(t *testing.T) {
		date := Date{0, 0, 0, 0, 0, 0, 0, 0}
		assert.True(t, date.IsZero())
	})

	t.Run("zero date - from NewDateFromUnix(0)", func(t *testing.T) {
		date, err := NewDateFromUnix(0)
		require.NoError(t, err)
		assert.True(t, date.IsZero())
	})

	t.Run("zero date - from NewDateFromMillis(0)", func(t *testing.T) {
		date, err := NewDateFromMillis(0)
		require.NoError(t, err)
		assert.True(t, date.IsZero())
	})

	t.Run("non-zero date - single byte", func(t *testing.T) {
		date := Date{0, 0, 0, 0, 0, 0, 0, 1}
		assert.False(t, date.IsZero())
	})

	t.Run("non-zero date - first byte", func(t *testing.T) {
		date := Date{1, 0, 0, 0, 0, 0, 0, 0}
		assert.False(t, date.IsZero())
	})

	t.Run("non-zero date - middle byte", func(t *testing.T) {
		date := Date{0, 0, 0, 1, 0, 0, 0, 0}
		assert.False(t, date.IsZero())
	})

	t.Run("non-zero date - from timestamp", func(t *testing.T) {
		date, err := NewDateFromUnix(1234567890)
		require.NoError(t, err)
		assert.False(t, date.IsZero())
	})

	t.Run("non-zero date - all bytes set", func(t *testing.T) {
		date := Date{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
		assert.False(t, date.IsZero())
	})

	t.Run("existing test date", func(t *testing.T) {
		// From TestTimeFromMilliseconds
		next_day := Date{0x00, 0x00, 0x00, 0x00, 0x05, 0x26, 0x5c, 0x00}
		assert.False(t, next_day.IsZero())
	})
}

// TestDateIntegration tests integration with existing Date methods.
func TestDateIntegration(t *testing.T) {
	t.Run("NewDateFromUnix with Time() method", func(t *testing.T) {
		timestamp := int64(1234567890)
		date, err := NewDateFromUnix(timestamp)
		require.NoError(t, err)

		recoveredTime := date.Time()
		assert.Equal(t, timestamp, recoveredTime.Unix())
	})

	t.Run("NewDateFromMillis with Time() method", func(t *testing.T) {
		millis := int64(1234567890000)
		date, err := NewDateFromMillis(millis)
		require.NoError(t, err)

		recoveredTime := date.Time()
		expectedTimestamp := millis / 1000
		assert.Equal(t, expectedTimestamp, recoveredTime.Unix())
	})

	t.Run("DateFromTime with IsZero", func(t *testing.T) {
		// Zero time
		zeroTime := time.Unix(0, 0)
		date, err := DateFromTime(zeroTime)
		require.NoError(t, err)
		assert.True(t, date.IsZero())

		// Non-zero time
		nonZeroTime := time.Unix(1234567890, 0)
		date2, err := DateFromTime(nonZeroTime)
		require.NoError(t, err)
		assert.False(t, date2.IsZero())
	})

	t.Run("ReadDate with IsZero", func(t *testing.T) {
		// Create zero date bytes
		zeroBytes := make([]byte, 8)
		date, remainder, err := ReadDate(zeroBytes)
		require.NoError(t, err)
		assert.Empty(t, remainder)
		assert.True(t, date.IsZero())

		// Create non-zero date bytes
		nonZeroBytes := []byte{0x00, 0x00, 0x00, 0x00, 0x05, 0x26, 0x5c, 0x00}
		date2, remainder2, err := ReadDate(nonZeroBytes)
		require.NoError(t, err)
		assert.Empty(t, remainder2)
		assert.False(t, date2.IsZero())
	})

	t.Run("NewDate with IsZero", func(t *testing.T) {
		zeroBytes := make([]byte, 8)
		date, remainder, err := NewDate(zeroBytes)
		require.NoError(t, err)
		require.NotNil(t, date)
		assert.Empty(t, remainder)
		assert.True(t, date.IsZero())
	})
}

// TestDateEdgeCases tests edge cases and boundary conditions.
func TestDateEdgeCases(t *testing.T) {
	t.Run("date from current time", func(t *testing.T) {
		now := time.Now()
		date, err := DateFromTime(now)
		require.NoError(t, err)
		require.NotNil(t, date)

		// Recovered time should be close to original (within millisecond precision)
		recoveredTime := date.Time()
		diff := now.Sub(recoveredTime).Abs()
		assert.Less(t, diff, time.Millisecond*2)
	})

	t.Run("unix epoch", func(t *testing.T) {
		epoch := time.Unix(0, 0)
		date, err := DateFromTime(epoch)
		require.NoError(t, err)
		assert.True(t, date.IsZero())
		assert.Equal(t, int64(0), date.Time().Unix())
	})

	t.Run("recent date - 2020", func(t *testing.T) {
		// Jan 1, 2020
		date2020 := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
		date, err := DateFromTime(date2020)
		require.NoError(t, err)
		require.NotNil(t, date)
		assert.False(t, date.IsZero())

		recovered := date.Time()
		assert.Equal(t, date2020.Unix(), recovered.Unix())
	})

	t.Run("far future date", func(t *testing.T) {
		// Year 3000
		future := time.Date(3000, 1, 1, 0, 0, 0, 0, time.UTC)
		date, err := DateFromTime(future)
		require.NoError(t, err)
		require.NotNil(t, date)
		assert.False(t, date.IsZero())
	})

	t.Run("millisecond boundary - 999ms", func(t *testing.T) {
		millis := int64(1000000000999) // .999 seconds
		date, err := NewDateFromMillis(millis)
		require.NoError(t, err)
		assert.False(t, date.IsZero())
	})

	t.Run("conversion consistency", func(t *testing.T) {
		// Test that different constructors produce consistent results
		timestamp := int64(1234567890)
		millis := timestamp * 1000
		goTime := time.Unix(timestamp, 0)

		date1, err := NewDateFromUnix(timestamp)
		require.NoError(t, err)

		date2, err := NewDateFromMillis(millis)
		require.NoError(t, err)

		date3, err := DateFromTime(goTime)
		require.NoError(t, err)

		// All three should produce the same result
		assert.Equal(t, date1.Bytes(), date2.Bytes())
		assert.Equal(t, date1.Bytes(), date3.Bytes())
	})
}

// TestDateRoundTrip tests round-trip serialization and parsing.
func TestDateRoundTrip(t *testing.T) {
	t.Run("round trip via bytes", func(t *testing.T) {
		original, err := NewDateFromUnix(1234567890)
		require.NoError(t, err)

		bytes := original.Bytes()
		recovered, remainder, err := ReadDate(bytes)
		require.NoError(t, err)
		assert.Empty(t, remainder)

		assert.Equal(t, original.Bytes(), recovered.Bytes())
		assert.Equal(t, original.IsZero(), recovered.IsZero())
		assert.Equal(t, original.Time().Unix(), recovered.Time().Unix())
	})

	t.Run("round trip via NewDate", func(t *testing.T) {
		original, err := NewDateFromMillis(1234567890123)
		require.NoError(t, err)

		bytes := original.Bytes()
		recovered, remainder, err := NewDate(bytes)
		require.NoError(t, err)
		require.NotNil(t, recovered)
		assert.Empty(t, remainder)

		assert.Equal(t, original.Bytes(), recovered.Bytes())
	})

	t.Run("multiple dates in sequence", func(t *testing.T) {
		date1, err := NewDateFromUnix(1000)
		require.NoError(t, err)

		date2, err := NewDateFromUnix(2000)
		require.NoError(t, err)

		// Combine two dates
		combined := append(date1.Bytes(), date2.Bytes()...)

		// Read first date
		recovered1, remainder, err := ReadDate(combined)
		require.NoError(t, err)
		assert.Len(t, remainder, 8)
		assert.Equal(t, date1.Bytes(), recovered1.Bytes())

		// Read second date
		recovered2, remainder2, err := ReadDate(remainder)
		require.NoError(t, err)
		assert.Empty(t, remainder2)
		assert.Equal(t, date2.Bytes(), recovered2.Bytes())
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
