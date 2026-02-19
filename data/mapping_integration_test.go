package data

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMappingValidateIntegration tests Validate with various mapping states.
func TestMappingValidateIntegration(t *testing.T) {
	t.Run("validate after GoMapToMapping", func(t *testing.T) {
		gomap := map[string]string{"key1": "value1", "key2": "value2"}
		mapping, err := GoMapToMapping(gomap)
		require.NoError(t, err)
		require.NoError(t, mapping.Validate())
		require.True(t, mapping.IsValid())
	})

	t.Run("validate checks all key-value pairs", func(t *testing.T) {
		mapping, _, errs := NewMapping([]byte{0x00, 0x0c, 0x01, 0x61, 0x3d, 0x01, 0x62, 0x3b, 0x01, 0x63, 0x3d, 0x01, 0x64, 0x3b})
		require.Empty(t, errs)

		err := mapping.Validate()
		require.NoError(t, err)

		values := mapping.Values()
		require.Len(t, values, 2)

		for i, pair := range values {
			_, keyErr := pair[0].Data()
			_, valErr := pair[1].Data()
			require.NoError(t, keyErr, "key at position %d should be valid", i)
			require.NoError(t, valErr, "value at position %d should be valid", i)
		}
	})

	t.Run("validate with single key-value pair", func(t *testing.T) {
		mapping, _, errs := NewMapping([]byte{0x00, 0x06, 0x01, 0x61, 0x3d, 0x01, 0x62, 0x3b})
		require.Empty(t, errs)
		require.NoError(t, mapping.Validate())

		values := mapping.Values()
		require.Len(t, values, 1)

		key, err := values[0][0].Data()
		require.NoError(t, err)
		assert.Equal(t, "a", key)

		val, err := values[0][1].Data()
		require.NoError(t, err)
		assert.Equal(t, "b", val)
	})
}

// TestMappingDataRoundTrip verifies that a Mapping can be serialized
// with Data() and re-parsed with ReadMapping to produce identical results.
func TestMappingDataRoundTrip(t *testing.T) {
	t.Run("single pair round trip", func(t *testing.T) {
		gomap := map[string]string{"host": "127.0.0.1"}
		original, err := GoMapToMapping(gomap)
		require.NoError(t, err)

		serialized := original.Data()
		require.NotNil(t, serialized)

		reparsed, remainder, errs := ReadMapping(serialized)
		assert.Empty(t, errs, "Round-trip should produce no errors")
		assert.Empty(t, remainder, "Round-trip should consume all data")

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

// TestMappingDataUnicodeDelimiters tests round-trip with values containing delimiters.
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

// TestToGoMapRoundTrip tests round-trip preservation.
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
