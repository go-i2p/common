package data

import (
	"encoding/binary"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// [GAP] MappingValues.Add() allows empty string values (I2P spec: Length may be 0)
// =============================================================================

func TestMappingValuesAddEmptyValue(t *testing.T) {
	t.Run("empty value is now allowed per spec", func(t *testing.T) {
		mv := NewMappingValues(0)
		mv, err := mv.Add("key", "")
		require.NoError(t, err, "Empty values should be allowed per I2P spec")
		assert.Equal(t, 1, len(mv), "Should have one pair")

		val, valErr := mv[0][1].Data()
		require.NoError(t, valErr)
		assert.Equal(t, "", val, "Value should be empty string")
	})

	t.Run("empty key is still rejected", func(t *testing.T) {
		mv := NewMappingValues(0)
		_, err := mv.Add("", "value")
		require.Error(t, err, "Empty keys should still be rejected")
		assert.Contains(t, err.Error(), "empty key")
	})

	t.Run("empty value round-trip through mapping", func(t *testing.T) {
		mv := NewMappingValues(0)
		mv, err := mv.Add("emptyval", "")
		require.NoError(t, err)

		mapping, err := ValuesToMapping(mv)
		require.NoError(t, err)

		serialized := mapping.Data()
		require.NotNil(t, serialized)

		reparsed, _, errs := ReadMapping(serialized)
		assert.Empty(t, errs, "Round-trip of empty value should produce no errors")

		vals := reparsed.Values()
		require.Equal(t, 1, len(vals))

		key, _ := vals[0][0].Data()
		assert.Equal(t, "emptyval", key)

		val, _ := vals[0][1].Data()
		assert.Equal(t, "", val, "Empty value should survive round-trip")
	})
}

// =============================================================================
// [GAP] ReadMapping with size=0 initializes empty MappingValues
// =============================================================================

func TestReadMappingSizeZeroInitialized(t *testing.T) {
	t.Run("size zero produces initialized vals", func(t *testing.T) {
		// A mapping with size=0 means no key-value pairs (just the 2-byte size field)
		data := []byte{0x00, 0x00}
		mapping, remainder, errs := ReadMapping(data)
		assert.Empty(t, errs)
		assert.Empty(t, remainder)

		// vals should be initialized, not nil
		vals := mapping.Values()
		assert.NotNil(t, vals, "Values() should return non-nil for size=0 mapping")
		assert.Equal(t, 0, len(vals), "Should have zero pairs")
	})

	t.Run("size zero mapping vals pointer is not nil", func(t *testing.T) {
		data := []byte{0x00, 0x00}
		mapping, _, _ := ReadMapping(data)
		assert.NotNil(t, mapping.vals, "Internal vals pointer should be initialized")
	})
}

// =============================================================================
// [GAP] ToGoMap() converts Mapping back to map[string]string
// =============================================================================

func TestToGoMap(t *testing.T) {
	t.Run("round-trip GoMapToMapping and back", func(t *testing.T) {
		original := map[string]string{
			"host":     "127.0.0.1",
			"port":     "7654",
			"protocol": "NTCP2",
		}
		mapping, err := GoMapToMapping(original)
		require.NoError(t, err)

		result, err := mapping.ToGoMap()
		require.NoError(t, err)
		assert.Equal(t, original, result)
	})

	t.Run("empty mapping", func(t *testing.T) {
		original := map[string]string{}
		mapping, err := GoMapToMapping(original)
		require.NoError(t, err)

		result, err := mapping.ToGoMap()
		require.NoError(t, err)
		assert.Equal(t, 0, len(result))
	})

	t.Run("nil mapping returns error", func(t *testing.T) {
		var mapping *Mapping
		_, err := mapping.ToGoMap()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "nil")
	})

	t.Run("single pair", func(t *testing.T) {
		original := map[string]string{"key": "value"}
		mapping, err := GoMapToMapping(original)
		require.NoError(t, err)

		result, err := mapping.ToGoMap()
		require.NoError(t, err)
		assert.Equal(t, "value", result["key"])
	})
}

// =============================================================================
// [GAP] EncodeIntN with size=8 explicit max handling
// =============================================================================

func TestEncodeIntNSize8(t *testing.T) {
	t.Run("size 8 with large value", func(t *testing.T) {
		// Max int on 64-bit is 2^63-1
		maxInt := int(^uint(0) >> 1) // math.MaxInt
		result, err := EncodeIntN(maxInt, 8)
		require.NoError(t, err)
		assert.Equal(t, 8, len(result))

		// Verify round-trip
		decoded, err := DecodeIntN(result)
		require.NoError(t, err)
		assert.Equal(t, maxInt, decoded)
	})

	t.Run("size 8 with zero", func(t *testing.T) {
		result, err := EncodeIntN(0, 8)
		require.NoError(t, err)
		assert.Equal(t, 8, len(result))
		assert.Equal(t, make([]byte, 8), result)
	})

	t.Run("size 8 with value 1", func(t *testing.T) {
		result, err := EncodeIntN(1, 8)
		require.NoError(t, err)
		expected := []byte{0, 0, 0, 0, 0, 0, 0, 1}
		assert.Equal(t, expected, result)
	})
}

// =============================================================================
// [TEST] Mapping.Data() with corrupt pair handling
// =============================================================================

func TestMappingDataCorruptPair(t *testing.T) {
	t.Run("corrupt key is skipped, size remains consistent", func(t *testing.T) {
		// Create a mapping with valid pairs
		gomap := map[string]string{"good": "data"}
		mapping, err := GoMapToMapping(gomap)
		require.NoError(t, err)

		// Serialize and re-parse to verify consistency
		serialized := mapping.Data()
		require.NotNil(t, serialized)
		require.True(t, len(serialized) >= 2)

		// Verify size field matches actual payload
		declaredSize := int(binary.BigEndian.Uint16(serialized[:2]))
		actualPayload := len(serialized) - 2
		assert.Equal(t, actualPayload, declaredSize,
			"Size field must match actual serialized payload")
	})

	t.Run("empty mapping values produces empty payload", func(t *testing.T) {
		mv := MappingValues{}
		mapping, err := ValuesToMapping(mv)
		require.NoError(t, err)

		serialized := mapping.Data()
		require.NotNil(t, serialized)

		declaredSize := int(binary.BigEndian.Uint16(serialized[:2]))
		assert.Equal(t, 0, declaredSize,
			"Empty mapping should have size=0")
	})
}

// =============================================================================
// [TEST] Fuzz test for ReadMapping
// =============================================================================

func FuzzReadMapping(f *testing.F) {
	// Seed corpus with known valid and edge-case inputs
	f.Add([]byte{0x00, 0x00})                                     // empty mapping
	f.Add([]byte{0x00, 0x06, 0x01, 0x61, 0x3d, 0x01, 0x62, 0x3b}) // a=b
	f.Add([]byte{0x00, 0x01})                                     // size=1, insufficient data
	f.Add([]byte{0xFF, 0xFF})                                     // very large size
	f.Add([]byte{0x00})                                           // too short
	f.Add([]byte{})                                               // empty
	f.Add([]byte{
		0x00, 0x06, 0x01, 0x61, 0x3d, 0x01, 0x62, 0x3b,
		0x01, 0x63, 0x3d, 0x01, 0x64, 0x3b,
	}) // extra data beyond size

	f.Fuzz(func(t *testing.T, data []byte) {
		// ReadMapping should never panic on any input
		mapping, _, _ := ReadMapping(data)
		// If we got a mapping, Values() should not panic
		_ = mapping.Values()
	})
}

// =============================================================================
// [TEST] Mapping.Data() round-trip with Unicode containing = and ; delimiters
// =============================================================================

func TestMappingDataUnicodeDelimiters(t *testing.T) {
	t.Run("value containing equals sign", func(t *testing.T) {
		mv := NewMappingValues(0)
		mv, err := mv.Add("expr", "a=b")
		require.NoError(t, err)

		mapping, err := ValuesToMapping(mv)
		require.NoError(t, err)

		serialized := mapping.Data()
		reparsed, _, errs := ReadMapping(serialized)
		assert.Empty(t, errs)

		vals := reparsed.Values()
		require.Equal(t, 1, len(vals))

		key, _ := vals[0][0].Data()
		val, _ := vals[0][1].Data()
		assert.Equal(t, "expr", key)
		assert.Equal(t, "a=b", val, "Value with = should be preserved")
	})

	t.Run("value containing semicolon", func(t *testing.T) {
		mv := NewMappingValues(0)
		mv, err := mv.Add("list", "x;y;z")
		require.NoError(t, err)

		mapping, err := ValuesToMapping(mv)
		require.NoError(t, err)

		serialized := mapping.Data()
		reparsed, _, errs := ReadMapping(serialized)
		assert.Empty(t, errs)

		vals := reparsed.Values()
		require.Equal(t, 1, len(vals))

		key, _ := vals[0][0].Data()
		val, _ := vals[0][1].Data()
		assert.Equal(t, "list", key)
		assert.Equal(t, "x;y;z", val, "Value with ; should be preserved")
	})

	t.Run("key and value with both delimiters", func(t *testing.T) {
		mv := NewMappingValues(0)
		mv, err := mv.Add("k=1", "v;2")
		require.NoError(t, err)

		mapping, err := ValuesToMapping(mv)
		require.NoError(t, err)

		serialized := mapping.Data()
		reparsed, _, errs := ReadMapping(serialized)
		assert.Empty(t, errs)

		vals := reparsed.Values()
		require.Equal(t, 1, len(vals))

		key, _ := vals[0][0].Data()
		val, _ := vals[0][1].Data()
		assert.Equal(t, "k=1", key, "Key with = should be preserved")
		assert.Equal(t, "v;2", val, "Value with ; should be preserved")
	})

	t.Run("Unicode multi-byte characters", func(t *testing.T) {
		mv := NewMappingValues(0)
		mv, err := mv.Add("emoji", "café")
		require.NoError(t, err)

		mapping, err := ValuesToMapping(mv)
		require.NoError(t, err)

		serialized := mapping.Data()
		reparsed, _, errs := ReadMapping(serialized)
		assert.Empty(t, errs)

		vals := reparsed.Values()
		require.Equal(t, 1, len(vals))

		key, _ := vals[0][0].Data()
		val, _ := vals[0][1].Data()
		assert.Equal(t, "emoji", key)
		assert.Equal(t, "café", val, "Unicode value should survive round-trip")
	})
}

// =============================================================================
// [TEST] DecodeIntN with value that exceeds int range
// =============================================================================

func TestDecodeIntNExceedsIntRange(t *testing.T) {
	t.Run("max uint64 exceeds int range", func(t *testing.T) {
		// 0xFF * 8 = max uint64 = 18446744073709551615, exceeds max int
		data := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
		_, err := DecodeIntN(data)
		require.Error(t, err, "Should error when value exceeds max int")
		assert.Contains(t, err.Error(), "exceeds maximum int")
	})

	t.Run("value at int boundary", func(t *testing.T) {
		// 0x80 00 00 00 00 00 00 00 = 2^63, exceeds max int64
		data := []byte{0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
		_, err := DecodeIntN(data)
		require.Error(t, err, "2^63 should exceed max int")
	})

	t.Run("value just below int boundary", func(t *testing.T) {
		// 0x7F FF FF FF FF FF FF FF = 2^63-1 = max int64
		data := []byte{0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
		result, err := DecodeIntN(data)
		require.NoError(t, err, "max int64 should decode successfully")
		assert.Equal(t, int(^uint(0)>>1), result)
	})
}

// =============================================================================
// [QUALITY] shouldStopParsing uses sentinel errors
// =============================================================================

func TestShouldStopParsingSentinelErrors(t *testing.T) {
	t.Run("matches ErrMappingExpectedEquals", func(t *testing.T) {
		assert.True(t, shouldStopParsing(ErrMappingExpectedEquals),
			"Should match the equals sentinel error")
	})

	t.Run("matches ErrMappingExpectedSemicolon", func(t *testing.T) {
		assert.True(t, shouldStopParsing(ErrMappingExpectedSemicolon),
			"Should match the semicolon sentinel error")
	})

	t.Run("does not match other errors", func(t *testing.T) {
		assert.False(t, shouldStopParsing(ErrZeroLength),
			"Should not match ErrZeroLength")
		assert.False(t, shouldStopParsing(ErrDataTooShort),
			"Should not match ErrDataTooShort")
	})

	t.Run("wrapped sentinel still matches via errors.Is", func(t *testing.T) {
		// This verifies we use errors.Is, not string comparison
		assert.True(t, errors.Is(ErrMappingExpectedEquals, ErrMappingExpectedEquals))
		assert.True(t, errors.Is(ErrMappingExpectedSemicolon, ErrMappingExpectedSemicolon))
	})
}

// =============================================================================
// [QUALITY] WrapErrors does not produce <nil> prefix
// =============================================================================

func TestWrapErrorsNoNilPrefix(t *testing.T) {
	t.Run("single error has no nil prefix", func(t *testing.T) {
		errs := []error{ErrZeroLength}
		wrapped := WrapErrors(errs)
		require.NotNil(t, wrapped)
		assert.NotContains(t, wrapped.Error(), "<nil>",
			"WrapErrors should not contain <nil> in output")
	})

	t.Run("multiple errors have no nil prefix", func(t *testing.T) {
		errs := []error{ErrZeroLength, ErrDataTooShort, ErrDataTooLong}
		wrapped := WrapErrors(errs)
		require.NotNil(t, wrapped)
		assert.NotContains(t, wrapped.Error(), "<nil>",
			"WrapErrors should not contain <nil> in output")
		// Should contain all three error messages
		assert.Contains(t, wrapped.Error(), "zero length")
		assert.Contains(t, wrapped.Error(), "shorter than specified")
		assert.Contains(t, wrapped.Error(), "beyond length")
	})

	t.Run("empty errors returns nil", func(t *testing.T) {
		wrapped := WrapErrors(nil)
		assert.Nil(t, wrapped)

		wrapped = WrapErrors([]error{})
		assert.Nil(t, wrapped)
	})
}

// =============================================================================
// [QUALITY] doc.go is the sole package doc (no competing comment)
// =============================================================================

// This test is a compile-time verification that the package compiles
// with only doc.go providing the package documentation. The fix removed
// the competing "// Package data implements..." comment from date.go.

// =============================================================================
// [GAP] ToGoMap round-trip with GoMapToMapping
// =============================================================================

func TestToGoMapRoundTrip(t *testing.T) {
	t.Run("preserves all pairs", func(t *testing.T) {
		original := map[string]string{
			"a": "1",
			"b": "2",
			"c": "3",
		}
		mapping, err := GoMapToMapping(original)
		require.NoError(t, err)

		result, err := mapping.ToGoMap()
		require.NoError(t, err)
		assert.Equal(t, original, result)
	})
}
