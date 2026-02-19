package data

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMappingOrderSortsValuesThenKeys verifies that mappingOrder sorts values lexicographically by key.
func TestMappingOrderSortsValuesThenKeys(t *testing.T) {
	values := createTestMappingValues()
	mappingOrder(values)
	verifyMappingOrder(t, values)
}

// createTestMappingValues constructs test data for mapping order verification.
func createTestMappingValues() MappingValues {
	a, _ := ToI2PString("a")
	b, _ := ToI2PString("b")
	aa, _ := ToI2PString("aa")
	ab, _ := ToI2PString("ab")
	ac, _ := ToI2PString("ac")

	return MappingValues{
		[2]I2PString{b, b},
		[2]I2PString{ac, a},
		[2]I2PString{ab, b},
		[2]I2PString{aa, a},
		[2]I2PString{a, a},
	}
}

// verifyMappingOrder validates that values are sorted in the expected lexicographic order.
func verifyMappingOrder(t *testing.T, values MappingValues) {
	expectedKeys := []string{"a", "aa", "ab", "ac", "b"}

	for i, pair := range values {
		key, _ := pair[0].Data()
		validateKeyAtIndex(t, key, expectedKeys[i], i)
	}
}

// validateKeyAtIndex checks that the key at a specific index matches the expected value.
func validateKeyAtIndex(t *testing.T, actualKey, expectedKey string, index int) {
	if actualKey != expectedKey {
		t.Fatal(fmt.Sprintf("mappingOrder expected key %s, got %s at index %d", expectedKey, actualKey, index))
	}
}

// TestNewMappingValues tests the NewMappingValues constructor.
func TestNewMappingValues(t *testing.T) {
	t.Run("zero_capacity", func(t *testing.T) {
		mv := NewMappingValues(0)
		assert.NotNil(t, mv, "should create non-nil MappingValues")
		assert.Equal(t, 0, len(mv), "should have zero length")
	})

	t.Run("with_capacity", func(t *testing.T) {
		mv := NewMappingValues(10)
		assert.NotNil(t, mv, "should create non-nil MappingValues")
		assert.Equal(t, 0, len(mv), "should have zero length")
		assert.GreaterOrEqual(t, cap(mv), 10, "should have at least requested capacity")
	})

	t.Run("negative_capacity", func(t *testing.T) {
		mv := NewMappingValues(-5)
		assert.NotNil(t, mv, "should create non-nil MappingValues even with negative capacity")
		assert.Equal(t, 0, len(mv), "should have zero length")
	})
}

// TestMappingValuesAdd tests the Add method.
func TestMappingValuesAdd(t *testing.T) {
	t.Run("valid_pair", func(t *testing.T) {
		mv := NewMappingValues(0)
		mv, err := mv.Add("key1", "value1")
		require.NoError(t, err, "should add valid pair without error")
		assert.Equal(t, 1, len(mv), "should have one pair")

		// Verify key
		key, err := mv[0][0].DataSafe()
		require.NoError(t, err)
		assert.Equal(t, "key1", key)

		// Verify value
		val, err := mv[0][1].DataSafe()
		require.NoError(t, err)
		assert.Equal(t, "value1", val)
	})

	t.Run("multiple_pairs", func(t *testing.T) {
		mv := NewMappingValues(3)
		var err error

		mv, err = mv.Add("host", "127.0.0.1")
		require.NoError(t, err)

		mv, err = mv.Add("port", "7654")
		require.NoError(t, err)

		mv, err = mv.Add("protocol", "NTCP2")
		require.NoError(t, err)

		assert.Equal(t, 3, len(mv), "should have three pairs")
	})

	t.Run("empty_key", func(t *testing.T) {
		mv := NewMappingValues(0)
		_, err := mv.Add("", "value")
		assert.Error(t, err, "should reject empty key")
	})

	t.Run("empty_value", func(t *testing.T) {
		mv := NewMappingValues(0)
		mv, err := mv.Add("key", "")
		assert.NoError(t, err, "empty values are allowed per I2P spec: Length may be 0")
		assert.Equal(t, 1, len(mv), "should have one pair with empty value")
	})

	t.Run("key_too_long", func(t *testing.T) {
		mv := NewMappingValues(0)
		longKey := string(make([]byte, STRING_MAX_SIZE+1))
		_, err := mv.Add(longKey, "value")
		assert.Error(t, err, "should reject key exceeding max size")
	})

	t.Run("value_too_long", func(t *testing.T) {
		mv := NewMappingValues(0)
		longValue := string(make([]byte, STRING_MAX_SIZE+1))
		_, err := mv.Add("key", longValue)
		assert.Error(t, err, "should reject value exceeding max size")
	})

	t.Run("special_characters", func(t *testing.T) {
		mv := NewMappingValues(0)
		mv, err := mv.Add("key=special", "value;with;semicolons")
		require.NoError(t, err, "should handle special characters")

		key, _ := mv[0][0].DataSafe()
		val, _ := mv[0][1].DataSafe()
		assert.Equal(t, "key=special", key)
		assert.Equal(t, "value;with;semicolons", val)
	})

	t.Run("unicode", func(t *testing.T) {
		mv := NewMappingValues(0)
		mv, err := mv.Add("名前", "値")
		require.NoError(t, err, "should handle unicode")

		key, _ := mv[0][0].DataSafe()
		val, _ := mv[0][1].DataSafe()
		assert.Equal(t, "名前", key)
		assert.Equal(t, "値", val)
	})
}

// TestMappingValuesAddEmptyValue tests that empty values are allowed per I2P spec.
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
		mv := NewMappingValues(0)
		bigKey := string(make([]byte, 255))
		for i := range []byte(bigKey) {
			[]byte(bigKey)[i] = byte('a' + (i % 26))
		}
		bigVal := string(make([]byte, 255))
		for i := range []byte(bigVal) {
			[]byte(bigVal)[i] = byte('A' + (i % 26))
		}

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

// TestShouldStopParsingSentinelErrors tests that shouldStopParsing uses sentinel errors.
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
		assert.True(t, errors.Is(ErrMappingExpectedEquals, ErrMappingExpectedEquals))
		assert.True(t, errors.Is(ErrMappingExpectedSemicolon, ErrMappingExpectedSemicolon))
	})
}

// BenchmarkNewMappingValues benchmarks constructor performance.
func BenchmarkNewMappingValues(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = NewMappingValues(10)
	}
}

// BenchmarkMappingValuesAdd benchmarks Add method performance.
func BenchmarkMappingValuesAdd(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		mv := NewMappingValues(1)
		_, _ = mv.Add("key", "value")
	}
}

// BenchmarkMappingValuesValidate benchmarks Validate method performance.
func BenchmarkMappingValuesValidate(b *testing.B) {
	mv := NewMappingValues(3)
	mv, _ = mv.Add("key1", "value1")
	mv, _ = mv.Add("key2", "value2")
	mv, _ = mv.Add("key3", "value3")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = mv.Validate()
	}
}
