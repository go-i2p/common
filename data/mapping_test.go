package data

import (
	"bytes"
	"testing"

	"github.com/samber/oops"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValuesExclusesPairWithBadData(t *testing.T) {
	assert := assert.New(t)

	bad_key, _, errs := NewMapping([]byte{0x00, 0x0c, 0x01, 0x61, 0x3d, 0x01, 0x62, 0x3b, 0x00})
	values := bad_key.Values()

	e := WrapErrors(errs)
	t.Log(e)

	assert.NotNil(errs, "Values() did not return errors when some values had bad key")

	if assert.Equal(1, len(values), "Values() did not return valid values when some values had bad key") {
		k := values[0][0]
		key, _ := k.Data()
		v := values[0][1]
		val, _ := v.Data()
		assert.Equal(key, "a", "Values() returned by data with invalid key contains incorrect present key")
		assert.Equal(val, "b", "Values() returned by data with invalid key contains incorrect present key")
	}
}

func TestValuesWarnsMissingData(t *testing.T) {
	assert := assert.New(t)

	_, _, errs := NewMapping([]byte{0x00, 0x06, 0x01, 0x61, 0x3d, 0x01, 0x62})

	if assert.Equal(2, len(errs), "Values() reported wrong error count when mapping had missing data") {
		assert.Equal(errs[0].Error(), "warning parsing mapping: mapping length exceeds provided data")
	}
}

func TestValuesWarnsExtraData(t *testing.T) {
	assert := assert.New(t)

	mapping, _, errs := NewMapping([]byte{0x00, 0x06, 0x01, 0x61, 0x3d, 0x01, 0x62, 0x3b, 0x00})
	values := mapping.Values()

	key, kerr := values[0][0].Data()
	val, verr := values[0][1].Data()

	assert.Nil(kerr)
	assert.Nil(verr)
	assert.Equal(key, "a", "Values() did not return key in valid data")
	assert.Equal(val, "b", "Values() did not return value in valid data")

	if assert.Equal(1, len(errs), "Values() reported wrong error count when mapping had extra data") {
		assert.Equal("warning parsing mapping: data exists beyond length of mapping", errs[0].Error(), "correct error message should be returned")
	}
}

func TestValuesEnforcesEqualDelimitor(t *testing.T) {
	assert := assert.New(t)

	mapping, _, errs := NewMapping([]byte{0x00, 0x06, 0x01, 0x61, 0x30, 0x01, 0x62, 0x3b})
	values := mapping.Values()

	if assert.Equal(2, len(errs), "Values() reported wrong error count when mapping had = format error") {
		assert.Equal("mapping format violation, expected =", errs[0].Error(), "correct error message should be returned")
	}
	assert.Equal(0, len(values), "Values() not empty with invalid data due to = format error")
}

func TestValuesEnforcedSemicolonDelimitor(t *testing.T) {
	assert := assert.New(t)

	mapping, _, errs := NewMapping([]byte{0x00, 0x06, 0x01, 0x61, 0x3d, 0x01, 0x62, 0x30})
	values := mapping.Values()

	if assert.Equal(2, len(errs), "Values() reported wrong error count when mapping had ; format error") {
		assert.Equal("mapping format violation, expected ;", errs[0].Error(), "correct error message should be returned")
	}
	assert.Equal(0, len(values), "Values() not empty with invalid data due to ; format error")
}

func TestValuesReturnsValues(t *testing.T) {
	assert := assert.New(t)

	mapping, _, errs := NewMapping([]byte{0x00, 0x06, 0x01, 0x61, 0x3d, 0x01, 0x62, 0x3b})
	values := mapping.Values()

	key, kerr := values[0][0].Data()
	val, verr := values[0][1].Data()

	assert.Nil(errs, "Values() returned a errors with parsing valid data")
	assert.Nil(kerr)
	assert.Nil(verr)
	assert.Equal("a", key, "Values() did not return key in valid data")
	assert.Equal("b", val, "Values() did not return value in valid data")
}

func TestHasDuplicateKeysTrueWhenDuplicates(t *testing.T) {
	assert := assert.New(t)

	dups, _, _ := NewMapping([]byte{0x00, 0x0c, 0x01, 0x61, 0x3d, 0x01, 0x62, 0x3b, 0x01, 0x61, 0x3d, 0x01, 0x62, 0x3b})

	hasDups, err := dups.HasDuplicateKeys()
	assert.NoError(err, "HasDuplicateKeys() returned error with valid data")
	assert.Equal(true, hasDups, "HasDuplicateKeys() did not report true when duplicate keys present")
}

func TestHasDuplicateKeysFalseWithoutDuplicates(t *testing.T) {
	assert := assert.New(t)

	mapping, _, _ := NewMapping([]byte{0x00, 0x06, 0x01, 0x61, 0x3d, 0x01, 0x62, 0x3b})

	hasDups, err := mapping.HasDuplicateKeys()
	assert.NoError(err, "HasDuplicateKeys() returned error with valid data")
	assert.Equal(false, hasDups, "HasDuplicateKeys() did not report false when no duplicate keys present")
}

func TestReadMappingHasDuplicateKeys(t *testing.T) {
	assert := assert.New(t)

	_, _, errs := NewMapping([]byte{0x00, 0x0c, 0x01, 0x61, 0x3d, 0x01, 0x62, 0x3b, 0x01, 0x61, 0x3d, 0x01, 0x62, 0x3b})

	assert.Equal("mapping format violation, duplicate key in mapping", errs[0].Error(), "ReadMapping should throw an error when duplicate keys are present.")
}

func TestGoMapToMappingProducesCorrectMapping(t *testing.T) {
	assert := assert.New(t)

	gomap := map[string]string{"a": "b"}
	mapping, err := GoMapToMapping(gomap)

	assert.Nil(err, "GoMapToMapping() returned error with valid data")
	expected := []byte{0x00, 0x06, 0x01, 0x61, 0x3d, 0x01, 0x62, 0x3b}
	if bytes.Compare(mapping.Data(), expected) != 0 {
		t.Fatal("GoMapToMapping did not produce correct Mapping", mapping, expected)
	}
}

func TestFullGoMapToMappingProducesCorrectMapping(t *testing.T) {
	assert := assert.New(t)

	gomap := map[string]string{
		"a": "b",
		"c": "d",
	}
	mapping, err := GoMapToMapping(gomap)

	assert.Nil(err, "GoMapToMapping() returned error with valid data")
	expected := []byte{0x00, 0x0c, 0x01, 0x61, 0x3d, 0x01, 0x62, 0x3b, 0x01, 0x63, 0x3d, 0x01, 0x64, 0x3b}
	if bytes.Compare(mapping.Data(), expected) != 0 {
		t.Fatal("GoMapToMapping did not produce correct Mapping", mapping, expected)
	}
}

func TestStopValueReadTrueWhenCorrectErr(t *testing.T) {
	assert := assert.New(t)

	status := stopValueRead(ErrZeroLength)

	assert.Equal(true, status, "stopValueRead() did not return true when ErrZeroLength found")
}

func TestStopValueReadFalseWhenWrongErr(t *testing.T) {
	assert := assert.New(t)

	status := stopValueRead(oops.Errorf("something else"))

	assert.Equal(false, status, "stopValueRead() did not return false when non String error found")
}

func TestBeginsWithCorrectWhenTrue(t *testing.T) {
	assert := assert.New(t)

	slice := []byte{0x41}

	assert.Equal(true, beginsWith(slice, 0x41), "beginsWith() did not return true when correct")
}

func TestBeginsWithCorrectWhenFalse(t *testing.T) {
	assert := assert.New(t)

	slice := []byte{0x00}

	assert.Equal(false, beginsWith(slice, 0x41), "beginsWith() did not false when incorrect")
}

func TestBeginsWithCorrectWhenNil(t *testing.T) {
	assert := assert.New(t)

	slice := make([]byte, 0)

	assert.Equal(false, beginsWith(slice, 0x41), "beginsWith() did not return false on empty slice")
}

// TestMappingValidate tests the Validate method.
func TestMappingValidate(t *testing.T) {
	t.Run("valid mapping", func(t *testing.T) {
		mapping, _, errs := NewMapping([]byte{0x00, 0x06, 0x01, 0x61, 0x3d, 0x01, 0x62, 0x3b})
		require.Empty(t, errs)
		require.NoError(t, mapping.Validate())
		require.True(t, mapping.IsValid())
	})

	t.Run("valid mapping with multiple keys", func(t *testing.T) {
		mapping, _, _ := NewMapping([]byte{0x00, 0x0c, 0x01, 0x61, 0x3d, 0x01, 0x62, 0x3b, 0x01, 0x63, 0x3d, 0x01, 0x64, 0x3b})
		require.NoError(t, mapping.Validate())
		require.True(t, mapping.IsValid())
	})

	t.Run("nil mapping", func(t *testing.T) {
		var mapping *Mapping
		err := mapping.Validate()
		require.Error(t, err)
		require.Contains(t, err.Error(), "mapping is nil")
		require.False(t, mapping.IsValid())
	})

	t.Run("mapping with nil size", func(t *testing.T) {
		mapping := &Mapping{vals: &MappingValues{}}
		err := mapping.Validate()
		require.Error(t, err)
		require.Contains(t, err.Error(), "mapping size is nil")
		require.False(t, mapping.IsValid())
	})
}

// TestMappingIsValid tests the IsValid method.
func TestMappingIsValid(t *testing.T) {
	t.Run("valid mapping returns true", func(t *testing.T) {
		mapping, _, errs := NewMapping([]byte{0x00, 0x06, 0x01, 0x61, 0x3d, 0x01, 0x62, 0x3b})
		require.Empty(t, errs)
		assert.True(t, mapping.IsValid())
	})

	t.Run("nil mapping returns false", func(t *testing.T) {
		var mapping *Mapping
		assert.False(t, mapping.IsValid())
	})

	t.Run("mapping with nil size returns false", func(t *testing.T) {
		mapping := &Mapping{vals: &MappingValues{}}
		assert.False(t, mapping.IsValid())
	})
}

// TestHasDuplicateKeysErrorHandling tests error handling in HasDuplicateKeys.
func TestHasDuplicateKeysErrorHandling(t *testing.T) {
	t.Run("valid mapping with no duplicates", func(t *testing.T) {
		mapping, _, errs := NewMapping([]byte{0x00, 0x06, 0x01, 0x61, 0x3d, 0x01, 0x62, 0x3b})
		require.Empty(t, errs)

		hasDups, err := mapping.HasDuplicateKeys()
		require.NoError(t, err)
		assert.False(t, hasDups)
	})

	t.Run("valid mapping with duplicates", func(t *testing.T) {
		mapping, _, _ := NewMapping([]byte{0x00, 0x0c, 0x01, 0x61, 0x3d, 0x01, 0x62, 0x3b, 0x01, 0x61, 0x3d, 0x01, 0x63, 0x3b})

		hasDups, err := mapping.HasDuplicateKeys()
		require.NoError(t, err)
		assert.True(t, hasDups)
	})

	t.Run("empty mapping", func(t *testing.T) {
		mapping, _, errs := NewMapping([]byte{0x00, 0x00})
		// Empty mapping has a "zero length" error which is expected
		if len(errs) > 0 {
			require.Contains(t, errs[0].Error(), "zero length")
		}

		// Empty mapping should still be able to check for duplicates
		if mapping != nil && mapping.size != nil {
			hasDups, err := mapping.HasDuplicateKeys()
			require.NoError(t, err)
			assert.False(t, hasDups)
		}
	})
}

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
		// Create a valid mapping
		mapping, _, errs := NewMapping([]byte{0x00, 0x0c, 0x01, 0x61, 0x3d, 0x01, 0x62, 0x3b, 0x01, 0x63, 0x3d, 0x01, 0x64, 0x3b})
		require.Empty(t, errs)

		// Validate should succeed
		err := mapping.Validate()
		require.NoError(t, err)

		// Verify we can access all values
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

// TestMappingEdgeCases tests edge cases for Mapping validation.
func TestMappingEdgeCases(t *testing.T) {
	t.Run("mapping with max length strings", func(t *testing.T) {
		// Create a mapping with maximum length strings (255 bytes each)
		key := make([]byte, 255)
		val := make([]byte, 255)
		for i := range key {
			key[i] = 'k'
			val[i] = 'v'
		}

		keyStr, err := ToI2PString(string(key))
		require.NoError(t, err)
		valStr, err := ToI2PString(string(val))
		require.NoError(t, err)

		mapping, merr := ValuesToMapping(MappingValues{{keyStr, valStr}})
		require.NoError(t, merr)
		require.NoError(t, mapping.Validate())
		require.True(t, mapping.IsValid())

		hasDups, err := mapping.HasDuplicateKeys()
		require.NoError(t, err)
		assert.False(t, hasDups)
	})

	t.Run("mapping with empty strings", func(t *testing.T) {
		// Empty strings are valid in I2P mappings
		keyStr, err := ToI2PString("")
		require.NoError(t, err)
		valStr, err := ToI2PString("")
		require.NoError(t, err)

		mapping, merr := ValuesToMapping(MappingValues{{keyStr, valStr}})
		require.NoError(t, merr)
		require.NoError(t, mapping.Validate())
		require.True(t, mapping.IsValid())
	})

	t.Run("mapping with special characters", func(t *testing.T) {
		// Test with special characters that are not delimiters
		gomap := map[string]string{
			"key!@#":  "value$%^",
			"unicode": "日本語",
		}
		mapping, err := GoMapToMapping(gomap)
		require.NoError(t, err)
		require.NoError(t, mapping.Validate())
		require.True(t, mapping.IsValid())
	})
}

// BenchmarkMappingValidate benchmarks the Validate method.
func BenchmarkMappingValidate(b *testing.B) {
	mapping, _, _ := NewMapping([]byte{0x00, 0x0c, 0x01, 0x61, 0x3d, 0x01, 0x62, 0x3b, 0x01, 0x63, 0x3d, 0x01, 0x64, 0x3b})
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = mapping.Validate()
	}
}

// BenchmarkHasDuplicateKeys benchmarks the HasDuplicateKeys method.
func BenchmarkHasDuplicateKeys(b *testing.B) {
	mapping, _, _ := NewMapping([]byte{0x00, 0x0c, 0x01, 0x61, 0x3d, 0x01, 0x62, 0x3b, 0x01, 0x63, 0x3d, 0x01, 0x64, 0x3b})
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = mapping.HasDuplicateKeys()
	}
}
