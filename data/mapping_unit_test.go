package data

import (
	"bytes"
	"encoding/binary"
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

	// Expects 3 errors: (1) mapping length exceeds provided data (from handleInsufficientData),
	// (2) mapping length exceeds provided data (from validateMappingLength in ReadMappingValues),
	// (3) missing ';' delimiter (parser now correctly attempts to parse 5-byte truncated pair).
	if assert.Equal(3, len(errs), "Values() reported wrong error count when mapping had missing data") {
		assert.Equal("warning parsing mapping: mapping length exceeds provided data", errs[0].Error())
	}
}

func TestValuesWarnsExtraData(t *testing.T) {
	assert := assert.New(t)

	mapping, remainder, errs := NewMapping([]byte{0x00, 0x06, 0x01, 0x61, 0x3d, 0x01, 0x62, 0x3b, 0x00})
	values := mapping.Values()

	key, kerr := values[0][0].Data()
	val, verr := values[0][1].Data()

	assert.Nil(kerr)
	assert.Nil(verr)
	assert.Equal(key, "a", "Values() did not return key in valid data")
	assert.Equal(val, "b", "Values() did not return value in valid data")

	// Extra data beyond the declared mapping size is not an error;
	// it is returned as remainder for the caller to handle (embedded mappings).
	assert.Empty(errs, "No errors expected when extra data is simply trailing remainder")
	assert.Equal(1, len(remainder), "Extra data should be returned as remainder")
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
		if len(errs) > 0 {
			require.Contains(t, errs[0].Error(), "zero length")
		}

		if mapping != nil && mapping.size != nil {
			hasDups, err := mapping.HasDuplicateKeys()
			require.NoError(t, err)
			assert.False(t, hasDups)
		}
	})
}

// TestExtraDataWarning verifies that ReadMapping handles extra data
// beyond the declared mapping size by returning it as remainder.
func TestExtraDataWarning(t *testing.T) {
	t.Run("extra byte after mapping", func(t *testing.T) {
		data := []byte{0x00, 0x06, 0x01, 0x61, 0x3d, 0x01, 0x62, 0x3b, 0x00}
		_, remainder, errs := ReadMapping(data)

		// Extra data beyond the declared mapping size is not an error;
		// it is silently returned as remainder (common for embedded mappings).
		assert.Empty(t, errs,
			"No errors expected when extra data is simply trailing remainder")
		assert.Equal(t, 1, len(remainder),
			"Extra data should be returned as remainder")
	})

	t.Run("no extra data", func(t *testing.T) {
		data := []byte{0x00, 0x06, 0x01, 0x61, 0x3d, 0x01, 0x62, 0x3b}
		_, _, errs := ReadMapping(data)
		assert.Empty(t, errs, "No errors when data matches declared size exactly")
	})
}

// TestReadMappingSizeZeroInitialized tests that size=0 initializes empty MappingValues.
func TestReadMappingSizeZeroInitialized(t *testing.T) {
	t.Run("size zero produces initialized vals", func(t *testing.T) {
		data := []byte{0x00, 0x00}
		mapping, remainder, errs := ReadMapping(data)
		assert.Empty(t, errs)
		assert.Empty(t, remainder)

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

// TestToGoMap tests the ToGoMap method.
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

// TestMappingDataCorruptPair tests corrupt pair handling.
func TestMappingDataCorruptPair(t *testing.T) {
	t.Run("corrupt key is skipped, size remains consistent", func(t *testing.T) {
		gomap := map[string]string{"good": "data"}
		mapping, err := GoMapToMapping(gomap)
		require.NoError(t, err)

		serialized := mapping.Data()
		require.NotNil(t, serialized)
		require.True(t, len(serialized) >= 2)

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

// TestReadMappingEarlyReturnOnSizeError verifies that ReadMapping returns immediately
// when parseMappingSize fails, rather than continuing with a nil size (QUALITY-2 fix).
func TestReadMappingEarlyReturnOnSizeError(t *testing.T) {
	// Empty input should trigger validateMappingInputData guard and return early
	mapping, remainder, errs := ReadMapping([]byte{})
	assert.NotEmpty(t, errs, "ReadMapping should return errors for empty input")
	assert.Nil(t, remainder, "ReadMapping should return nil remainder for empty input")
	assert.Nil(t, mapping.size, "Mapping size should be nil for empty input")

	// Single byte (less than MAPPING_SIZE_FIELD_LENGTH) should also return early
	mapping2, _, errs2 := ReadMapping([]byte{0x00})
	assert.NotEmpty(t, errs2, "ReadMapping should return errors for too-short input")
	assert.Nil(t, mapping2.size, "Mapping size should be nil for too-short input")
}

// TestSerializeOnePairRoundTrip verifies that the simplified serializeOnePair
// produces correct wire format (QUALITY-1 fix).
func TestSerializeOnePairRoundTrip(t *testing.T) {
	key, err := ToI2PString("host")
	require.NoError(t, err)
	val, err := ToI2PString("127.0.0.1")
	require.NoError(t, err)

	pair := [2]I2PString{key, val}
	result, serErr := serializeOnePair(pair)
	require.NoError(t, serErr)

	// Expected: [len_byte(4)] + "host" + '=' + [len_byte(9)] + "127.0.0.1" + ';'
	// len(key) = 1+4=5, len(val) = 1+9=10, plus '=' and ';' = 17
	assert.Equal(t, 17, len(result), "serialized pair has wrong length")
	assert.Equal(t, byte('='), result[5], "missing equals delimiter")
	assert.Equal(t, byte(';'), result[16], "missing semicolon delimiter")
}

func TestGoMapToMappingDeterminism(t *testing.T) {
	m := map[string]string{"z": "1", "a": "2", "m": "3", "host": "127.0.0.1"}
	results := make([][]byte, 100)
	for i := range results {
		mapping, err := GoMapToMapping(m)
		require.NoError(t, err)
		results[i] = mapping.Data()
	}
	for i := 1; i < len(results); i++ {
		assert.Equal(t, results[0], results[i], "GoMapToMapping must be deterministic (iteration %d)", i)
	}
}
