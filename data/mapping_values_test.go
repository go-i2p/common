package data

import (
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
		mv, err := mv.Add("", "value")
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
		mv, err := mv.Add(longKey, "value")
		assert.Error(t, err, "should reject key exceeding max size")
	})

	t.Run("value_too_long", func(t *testing.T) {
		mv := NewMappingValues(0)
		longValue := string(make([]byte, STRING_MAX_SIZE+1))
		mv, err := mv.Add("key", longValue)
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

// TestMappingValuesValidate tests the Validate method.
func TestMappingValuesValidate(t *testing.T) {
	t.Run("valid_empty", func(t *testing.T) {
		mv := NewMappingValues(0)
		err := mv.Validate()
		assert.NoError(t, err, "empty MappingValues should be valid")
	})

	t.Run("valid_with_pairs", func(t *testing.T) {
		mv := NewMappingValues(0)
		mv, _ = mv.Add("key1", "value1")
		mv, _ = mv.Add("key2", "value2")

		err := mv.Validate()
		assert.NoError(t, err, "valid MappingValues should pass validation")
	})

	t.Run("invalid_key", func(t *testing.T) {
		// Create invalid MappingValues by direct construction
		invalidKey := I2PString{10, 'a', 'b'} // Claims 10 bytes, only has 2
		validValue, _ := NewI2PString("value")
		mv := MappingValues{
			[2]I2PString{invalidKey, validValue},
		}

		err := mv.Validate()
		assert.Error(t, err, "should detect invalid key")
		assert.Contains(t, err.Error(), "key at index 0", "error should mention key index")
	})

	t.Run("invalid_value", func(t *testing.T) {
		// Create invalid MappingValues by direct construction
		validKey, _ := NewI2PString("key")
		invalidValue := I2PString{10, 'a', 'b'} // Claims 10 bytes, only has 2
		mv := MappingValues{
			[2]I2PString{validKey, invalidValue},
		}

		err := mv.Validate()
		assert.Error(t, err, "should detect invalid value")
		assert.Contains(t, err.Error(), "value at index 0", "error should mention value index")
	})
}

// TestMappingValuesIsValid tests the IsValid method.
func TestMappingValuesIsValid(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		mv := NewMappingValues(0)
		mv, _ = mv.Add("key", "value")
		assert.True(t, mv.IsValid(), "valid MappingValues should return true")
	})

	t.Run("invalid", func(t *testing.T) {
		// Create invalid MappingValues
		invalidKey := I2PString{10, 'a'}
		validValue, _ := NewI2PString("value")
		mv := MappingValues{
			[2]I2PString{invalidKey, validValue},
		}
		assert.False(t, mv.IsValid(), "invalid MappingValues should return false")
	})
}

// TestMappingValuesRoundTrip tests creating, adding, and converting to Mapping.
func TestMappingValuesRoundTrip(t *testing.T) {
	mv := NewMappingValues(3)
	var err error

	mv, err = mv.Add("host", "127.0.0.1")
	require.NoError(t, err)

	mv, err = mv.Add("port", "7654")
	require.NoError(t, err)

	mv, err = mv.Add("protocol", "NTCP2")
	require.NoError(t, err)

	// Validate
	assert.NoError(t, mv.Validate(), "should be valid")
	assert.True(t, mv.IsValid(), "IsValid should return true")

	// Convert to Mapping
	mapping, merr := ValuesToMapping(mv)
	assert.NoError(t, merr, "should not error on valid mapping")
	assert.NotNil(t, mapping, "should create mapping")

	// Validate mapping
	assert.NoError(t, mapping.Validate(), "mapping should be valid")
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
