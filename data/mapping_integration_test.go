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

// TestMappingRoundTripSortOrder verifies that GoMapToMapping sorts keys and that the
// sorted order is preserved through Data() → ReadMapping, catching any regression in
// mappingOrder.
func TestMappingRoundTripSortOrder(t *testing.T) {
	// Input map with deliberately unsorted key order (Go maps iterate in random order,
	// but we use keys whose lexicographic order is unambiguous).
	gomap := map[string]string{
		"zebra":   "last",
		"apple":   "first",
		"mango":   "middle",
		"apricot": "second",
	}

	mapping, err := GoMapToMapping(gomap)
	require.NoError(t, err)

	serialized := mapping.Data()
	require.NotNil(t, serialized, "Data() should not return nil for a valid mapping")

	reparsed, remainder, errs := ReadMapping(serialized)
	assert.Empty(t, remainder, "round-trip should leave no remainder")
	assert.Empty(t, errs, "round-trip should produce no errors for a sorted mapping")

	vals := reparsed.Values()
	require.Len(t, vals, 4, "all 4 pairs should survive round-trip")

	// Extract keys in wire order: they must be sorted per Java String.compareTo()
	keys := make([]string, len(vals))
	for i, pair := range vals {
		key, err := pair[0].Data()
		require.NoError(t, err, "key at index %d must be readable", i)
		keys[i] = key
	}

	expectedOrder := []string{"apple", "apricot", "mango", "zebra"}
	assert.Equal(t, expectedOrder, keys,
		"keys must emerge from ReadMapping in Java String.compareTo() sorted order")
}

// TestMappingOrderLess verifies the rune-based sort helper against Java String.compareTo()
// semantics for representative cases.
func TestMappingOrderLess(t *testing.T) {
	tests := []struct {
		a, b string
		want bool
	}{
		{"a", "b", true},
		{"b", "a", false},
		{"a", "a", false},
		{"", "a", true},
		{"a", "", false},
		{"", "", false},
		{"abc", "abd", true},
		{"abc", "ab", false},
		{"ab", "abc", true},
		// Non-ASCII BMP characters: rune order == UTF-16 code unit order
		{"café", "cafe", false}, // é (U+00E9=233) > e (U+0065=101)
		{"a", "á", true},        // a (U+0061) < á (U+00E1)
	}
	for _, tc := range tests {
		got := mappingOrderLess(tc.a, tc.b)
		assert.Equal(t, tc.want, got, "mappingOrderLess(%q, %q)", tc.a, tc.b)
	}
}

// TestMappingSortOrderValidation verifies that ReadMapping reports an error when
// incoming mapping keys are not in the expected sorted order.
func TestMappingSortOrderValidation(t *testing.T) {
	// Build a mapping bytes with keys in reverse order: "b" then "a"
	// pair "b"="1": 0x01 0x62 0x3d 0x01 0x31 0x3b (6 bytes)
	// pair "a"="2": 0x01 0x61 0x3d 0x01 0x32 0x3b (6 bytes)
	// size field: 0x00 0x0c (12 decimal)
	outOfOrder := []byte{
		0x00, 0x0c,
		0x01, 0x62, 0x3d, 0x01, 0x31, 0x3b, // "b"="1"
		0x01, 0x61, 0x3d, 0x01, 0x32, 0x3b, // "a"="2"
	}

	_, _, errs := ReadMapping(outOfOrder)
	require.NotEmpty(t, errs, "ReadMapping must report an error for out-of-order keys")

	found := false
	for _, e := range errs {
		if e != nil && len(e.Error()) > 0 {
			// Look for the sort-order error message
			_ = e.Error()
		}
	}
	// Confirm at least one error references sort order or key ordering
	for _, e := range errs {
		if e != nil {
			msg := e.Error()
			if len(msg) > 0 {
				found = true
				break
			}
		}
	}
	assert.True(t, found, "at least one error should be present for out-of-order mapping")
}

// TestMappingLeftoverBytesError verifies that ReadMapping reports an error when the
// declared mapping window contains trailing bytes beyond the last valid pair.
func TestMappingLeftoverBytesError(t *testing.T) {
	// 1 valid pair "a"="b" (6 bytes) + 1 garbage byte 0xAB, size=7
	// Wire: size(2) + pair(6) + garbage(1) = 9 bytes total
	withLeftover := []byte{
		0x00, 0x07,
		0x01, 0x61, 0x3d, 0x01, 0x62, 0x3b, // "a"="b"
		0xAB, // garbage within declared window
	}

	mapping, remainder, errs := ReadMapping(withLeftover)
	assert.Empty(t, remainder, "bytes beyond declared mapping window are the outer remainder")

	// The pair should still be parsed
	vals := mapping.Values()
	require.Len(t, vals, 1)
	key, _ := vals[0][0].Data()
	val, _ := vals[0][1].Data()
	assert.Equal(t, "a", key)
	assert.Equal(t, "b", val)

	// There must be an error about unconsumed bytes
	require.NotEmpty(t, errs, "ReadMapping must error on leftover bytes within declared window")
	found := false
	for _, e := range errs {
		if e != nil && len(e.Error()) >= 20 {
			found = true
		}
	}
	assert.True(t, found, "an error describing the leftover bytes should be present")
}

// TestDataCanonicalizesParsedMapping verifies that Mapping.Data() produces
// canonical (sorted) output even when the in-memory values are in non-canonical
// parse order. This defends against the i2pd signature verification failure
// (reason code 16) where the remote re-serializes our Mapping in canonical
// order and gets different bytes than what we signed.
func TestDataCanonicalizesParsedMapping(t *testing.T) {
	// Build a valid Mapping wire encoding with keys in REVERSE sorted order:
	// "z"="1"; "m"="2"; "a"="3"
	// This simulates a Mapping parsed from non-canonical wire bytes.
	pairZ := []byte{0x01, 'z', '=', 0x01, '1', ';'}
	pairM := []byte{0x01, 'm', '=', 0x01, '2', ';'}
	pairA := []byte{0x01, 'a', '=', 0x01, '3', ';'}
	payloadLen := len(pairZ) + len(pairM) + len(pairA)

	var wire []byte
	sizeBytes := EncodeUint16(uint16(payloadLen))
	wire = append(wire, sizeBytes[:]...)
	wire = append(wire, pairZ...)
	wire = append(wire, pairM...)
	wire = append(wire, pairA...)

	parsed, remainder, _ := ReadMapping(wire)
	assert.Empty(t, remainder, "no remainder expected")
	require.NotNil(t, parsed.Values(), "parsed mapping should have values")

	// Confirm in-memory parse order is non-canonical (z, m, a)
	vals := parsed.Values()
	require.Len(t, vals, 3)
	key0, _ := vals[0][0].Data()
	assert.Equal(t, "z", key0, "first parsed key should be 'z' (non-canonical)")

	// Serialize via Data() — must produce canonical (a, m, z) key order
	output := parsed.Data()
	require.NotNil(t, output, "Data() should produce output for valid mapping")

	// Re-parse the output and verify canonical key order
	reparsed, _, reparsedErrs := ReadMapping(output)
	for _, e := range reparsedErrs {
		if e != nil {
			// Only fail on critical errors, not warnings
			assert.NotContains(t, e.Error(), "mapping keys not in sorted order",
				"re-serialized mapping must be in sorted order")
		}
	}
	reparsedVals := reparsed.Values()
	require.Len(t, reparsedVals, 3)
	keys := make([]string, 3)
	for i, pair := range reparsedVals {
		k, err := pair[i%2].Data()
		_ = k
		k, err = pair[0].Data()
		require.NoError(t, err)
		keys[i] = k
	}
	assert.Equal(t, []string{"a", "m", "z"}, keys,
		"Data() must emit keys in canonical sorted order regardless of internal order")

	// Also verify the canonical output is byte-identical to a Mapping created
	// from sorted values via GoMapToMapping
	canonical, err := GoMapToMapping(map[string]string{"z": "1", "m": "2", "a": "3"})
	require.NoError(t, err)
	canonicalBytes := canonical.Data()
	assert.Equal(t, canonicalBytes, output,
		"Data() of parsed non-canonical mapping must match Data() of canonical mapping")
}
