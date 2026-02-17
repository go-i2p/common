package data

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Tests for Critical Fix: Date.Time() integer overflow
// =============================================================================

// TestDateTimeNoOverflow verifies that Date.Time() uses time.UnixMilli
// instead of the overflow-prone multiplication (seconds.Int()*1000000).
func TestDateTimeNoOverflow(t *testing.T) {
	t.Run("large date near overflow boundary", func(t *testing.T) {
		// Year 2262 boundary: the old multiplication code would overflow int64
		// at approximately 9223372036854 milliseconds (2^63 / 1000000)
		// = year ~2262. With time.UnixMilli, this works correctly.
		millis := int64(9223372036854) // Near the old overflow boundary
		var date Date
		binary.BigEndian.PutUint64(date[:], uint64(millis))

		result := date.Time()
		// Should not overflow; the time should be valid and in the future
		assert.True(t, result.After(time.Date(2200, 1, 1, 0, 0, 0, 0, time.UTC)),
			"Date near overflow boundary should be far future, got %v", result)
	})

	t.Run("known date roundtrip", func(t *testing.T) {
		// 86400000 ms = exactly 1 day after epoch
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
		// Feb 2026 in milliseconds
		millis := int64(1771372800000) // ~2026-02-18
		var date Date
		binary.BigEndian.PutUint64(date[:], uint64(millis))

		result := date.Time()
		assert.True(t, result.Year() >= 2026, "Should parse to year 2026+")
	})
}

// =============================================================================
// Tests for Critical Fix: processNormalMappingData extra data detection
// =============================================================================

// TestExtraDataWarning verifies that ReadMapping warns when there is
// data beyond the declared mapping size.
func TestExtraDataWarning(t *testing.T) {
	t.Run("extra byte after mapping", func(t *testing.T) {
		// Size=6: key "a" + = + value "b" + ;, then extra 0x00 byte
		data := []byte{0x00, 0x06, 0x01, 0x61, 0x3d, 0x01, 0x62, 0x3b, 0x00}
		_, remainder, errs := ReadMapping(data)

		require.Equal(t, 1, len(errs),
			"Should produce exactly 1 warning for extra data")
		assert.Equal(t, "warning parsing mapping: data exists beyond length of mapping",
			errs[0].Error())
		assert.Equal(t, 1, len(remainder),
			"Extra data should be returned as remainder")
	})

	t.Run("no extra data", func(t *testing.T) {
		// Size=6: exact match
		data := []byte{0x00, 0x06, 0x01, 0x61, 0x3d, 0x01, 0x62, 0x3b}
		_, _, errs := ReadMapping(data)
		assert.Empty(t, errs, "No errors when data matches declared size exactly")
	})
}

// =============================================================================
// Tests for Critical Fix: Integer uses signed int but spec requires unsigned
// =============================================================================

// TestUintSafe verifies that UintSafe correctly handles unsigned values,
// including values >= 2^63 that would wrap negative with Int().
func TestUintSafe(t *testing.T) {
	t.Run("small value", func(t *testing.T) {
		i := Integer([]byte{0x00, 0x01})
		val, err := i.UintSafe()
		require.NoError(t, err)
		assert.Equal(t, uint64(1), val)
	})

	t.Run("max uint16", func(t *testing.T) {
		i := Integer([]byte{0xFF, 0xFF})
		val, err := i.UintSafe()
		require.NoError(t, err)
		assert.Equal(t, uint64(65535), val)
	})

	t.Run("value above int63 boundary", func(t *testing.T) {
		// 0x80...00 = 2^63, which would wrap negative with Int()
		i := Integer([]byte{0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})

		// Int() returns negative (signed overflow)
		intVal := i.Int()
		assert.True(t, intVal < 0, "Int() should return negative for values >= 2^63")

		// UintSafe() returns correct unsigned value
		uintVal, err := i.UintSafe()
		require.NoError(t, err)
		assert.Equal(t, uint64(1)<<63, uintVal,
			"UintSafe() should correctly return 2^63")
	})

	t.Run("max uint64", func(t *testing.T) {
		i := Integer([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF})
		val, err := i.UintSafe()
		require.NoError(t, err)
		assert.Equal(t, uint64(0xFFFFFFFFFFFFFFFF), val)
	})

	t.Run("empty integer", func(t *testing.T) {
		i := Integer([]byte{})
		_, err := i.UintSafe()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "empty")
	})

	t.Run("too large integer", func(t *testing.T) {
		i := Integer(make([]byte, 9))
		_, err := i.UintSafe()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "too large")
	})

	t.Run("consistency with IntSafe for small values", func(t *testing.T) {
		testValues := []byte{0, 1, 127, 255}
		for _, v := range testValues {
			i := Integer([]byte{v})
			intVal, intErr := i.IntSafe()
			uintVal, uintErr := i.UintSafe()
			require.NoError(t, intErr)
			require.NoError(t, uintErr)
			assert.Equal(t, uint64(intVal), uintVal,
				"IntSafe and UintSafe should agree for value %d", v)
		}
	})
}

// =============================================================================
// Tests for Critical Fix: ValuesToMapping size overflow
// =============================================================================

// TestValuesToMappingSizeOverflow verifies that ValuesToMapping returns
// an error when the total mapping data exceeds 65535 bytes.
func TestValuesToMappingSizeOverflow(t *testing.T) {
	t.Run("normal size succeeds", func(t *testing.T) {
		mv := NewMappingValues(0)
		mv, err := mv.Add("key", "value")
		require.NoError(t, err)

		mapping, err := ValuesToMapping(mv)
		require.NoError(t, err)
		require.NotNil(t, mapping)
	})

	t.Run("oversized mapping returns error", func(t *testing.T) {
		// Create enough pairs to exceed 65535 bytes
		mv := NewMappingValues(0)
		// Each pair: 1-byte key len + 255 bytes key + = + 1-byte val len + 255 bytes val + ;
		// = 514 bytes per pair. Need ~128 pairs for 65535.
		bigKey := string(make([]byte, 255))
		for i := range []byte(bigKey) {
			[]byte(bigKey)[i] = byte('a' + (i % 26))
		}
		bigVal := string(make([]byte, 255))
		for i := range []byte(bigVal) {
			[]byte(bigVal)[i] = byte('A' + (i % 26))
		}

		// Need at least 128 pairs of max-size strings to exceed 65535
		for i := 0; i < 130; i++ {
			key := bigKey[:254] + string(rune('a'+(i%26)))
			val := bigVal[:254] + string(rune('A'+(i%26)))
			mv, _ = mv.Add(key, val)
		}

		mapping, err := ValuesToMapping(mv)
		require.Error(t, err)
		assert.Nil(t, mapping)
		assert.Contains(t, err.Error(), "exceeds maximum")
	})
}

// =============================================================================
// Tests for Critical Fix: Mapping.Data() nil guard
// =============================================================================

// TestMappingDataNilGuard verifies that Mapping.Data() returns nil
// instead of panicking when the mapping is not properly initialized.
func TestMappingDataNilGuard(t *testing.T) {
	t.Run("nil mapping", func(t *testing.T) {
		var mapping *Mapping
		result := mapping.Data()
		assert.Nil(t, result, "Data() on nil mapping should return nil")
	})

	t.Run("nil size field", func(t *testing.T) {
		mapping := &Mapping{vals: &MappingValues{}}
		result := mapping.Data()
		assert.Nil(t, result, "Data() with nil size should return nil")
	})

	t.Run("valid mapping", func(t *testing.T) {
		gomap := map[string]string{"a": "b"}
		mapping, err := GoMapToMapping(gomap)
		require.NoError(t, err)
		result := mapping.Data()
		assert.NotNil(t, result, "Data() on valid mapping should return bytes")
	})
}

// =============================================================================
// Tests for Critical Fix: ReadInteger bounds validation
// =============================================================================

// TestReadIntegerBoundsValidation verifies that ReadInteger validates
// the size parameter (must be 1-8).
func TestReadIntegerBoundsValidation(t *testing.T) {
	data := []byte{0x01, 0x02, 0x03, 0x04}

	t.Run("size zero returns nil", func(t *testing.T) {
		result, remainder := ReadInteger(data, 0)
		assert.Nil(t, result)
		assert.Equal(t, data, remainder, "Original data should be returned as remainder")
	})

	t.Run("negative size returns nil", func(t *testing.T) {
		result, remainder := ReadInteger(data, -1)
		assert.Nil(t, result)
		assert.Equal(t, data, remainder)
	})

	t.Run("size exceeds max returns nil", func(t *testing.T) {
		result, remainder := ReadInteger(data, 9)
		assert.Nil(t, result)
		assert.Equal(t, data, remainder)
	})

	t.Run("valid size 1", func(t *testing.T) {
		result, remainder := ReadInteger(data, 1)
		assert.Equal(t, Integer([]byte{0x01}), result)
		assert.Equal(t, []byte{0x02, 0x03, 0x04}, remainder)
	})

	t.Run("valid size 4", func(t *testing.T) {
		result, remainder := ReadInteger(data, 4)
		assert.Equal(t, Integer(data), result)
		assert.Empty(t, remainder)
	})

	t.Run("max valid size 8", func(t *testing.T) {
		bigData := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09}
		result, remainder := ReadInteger(bigData, 8)
		assert.Equal(t, Integer(bigData[:8]), result)
		assert.Equal(t, []byte{0x09}, remainder)
	})
}

// =============================================================================
// Tests for Quality Fix: stopValueRead uses errors.Is
// =============================================================================

// TestStopValueReadUsesErrorsIs verifies that stopValueRead matches
// using errors.Is(err, ErrZeroLength) instead of string comparison.
func TestStopValueReadUsesErrorsIs(t *testing.T) {
	t.Run("matches ErrZeroLength sentinel", func(t *testing.T) {
		assert.True(t, stopValueRead(ErrZeroLength),
			"Should match the ErrZeroLength sentinel error")
	})

	t.Run("does not match other errors", func(t *testing.T) {
		assert.False(t, stopValueRead(ErrDataTooShort),
			"Should not match ErrDataTooShort")
		assert.False(t, stopValueRead(ErrDataTooLong),
			"Should not match ErrDataTooLong")
	})
}

// =============================================================================
// Tests for Mapping.Data() round-trip serialization
// =============================================================================

// TestMappingDataRoundTrip verifies that a Mapping can be serialized
// with Data() and re-parsed with ReadMapping to produce identical results.
func TestMappingDataRoundTrip(t *testing.T) {
	t.Run("single pair round trip", func(t *testing.T) {
		gomap := map[string]string{"host": "127.0.0.1"}
		original, err := GoMapToMapping(gomap)
		require.NoError(t, err)

		// Serialize
		serialized := original.Data()
		require.NotNil(t, serialized)

		// Re-parse
		reparsed, remainder, errs := ReadMapping(serialized)
		assert.Empty(t, errs, "Round-trip should produce no errors")
		assert.Empty(t, remainder, "Round-trip should consume all data")

		// Compare values
		origVals := original.Values()
		reparsedVals := reparsed.Values()
		require.Equal(t, len(origVals), len(reparsedVals))

		for i := range origVals {
			origKey, _ := origVals[i][0].Data()
			reparsedKey, _ := reparsedVals[i][0].Data()
			assert.Equal(t, origKey, reparsedKey, "Keys should match at index %d", i)

			origVal, _ := origVals[i][1].Data()
			reparsedVal, _ := reparsedVals[i][1].Data()
			assert.Equal(t, origVal, reparsedVal, "Values should match at index %d", i)
		}
	})

	t.Run("multiple pairs round trip", func(t *testing.T) {
		gomap := map[string]string{
			"host":     "127.0.0.1",
			"port":     "7654",
			"protocol": "NTCP2",
		}
		original, err := GoMapToMapping(gomap)
		require.NoError(t, err)

		serialized := original.Data()
		reparsed, _, errs := ReadMapping(serialized)
		assert.Empty(t, errs)

		origVals := original.Values()
		reparsedVals := reparsed.Values()
		require.Equal(t, len(origVals), len(reparsedVals))
	})
}
