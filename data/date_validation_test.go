package data

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
