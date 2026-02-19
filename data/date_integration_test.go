package data

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
