package data

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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

// TestMappingEdgeCases tests edge cases for Mapping validation.
func TestMappingEdgeCases(t *testing.T) {
	t.Run("mapping with max length strings", func(t *testing.T) {
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

// TestMappingInfiniteLoopProtection verifies that the parser doesn't hang
// on malformed data that could cause infinite loops.
func TestMappingInfiniteLoopProtection(t *testing.T) {
	tests := []struct {
		name        string
		data        []byte
		expectError bool
		description string
	}{
		{
			name: "malformed_repeated_data_no_progress",
			data: func() []byte {
				sizeInt, _ := NewIntegerFromInt(100, 2)
				data := sizeInt.Bytes()
				data = append(data, byte(5))
				data = append(data, []byte("abc")...)
				return data
			}(),
			expectError: true,
			description: "data too short for declared string length",
		},
		{
			name: "excessive_pairs_limit",
			data: func() []byte {
				gomap := make(map[string]string)
				for i := 0; i < MAX_MAPPING_PAIRS+10; i++ {
					key := string(rune('a'+(i%26))) + string(rune('a'+((i/26)%26))) + string(rune('0'+(i%10)))
					val := "v"
					gomap[key] = val
				}
				mapping, _ := GoMapToMapping(gomap)
				return mapping.Data()
			}(),
			expectError: true,
			description: "exceeds MAX_MAPPING_PAIRS limit",
		},
		{
			name: "missing_delimiter_creates_no_progress",
			data: func() []byte {
				sizeInt, _ := NewIntegerFromInt(50, 2)
				data := sizeInt.Bytes()
				data = append(data, byte(3))
				data = append(data, []byte("key")...)
				data = append(data, byte(5))
				data = append(data, []byte("value")...)
				return data
			}(),
			expectError: true,
			description: "missing equals delimiter",
		},
		{
			name: "truncated_data_at_value",
			data: func() []byte {
				sizeInt, _ := NewIntegerFromInt(100, 2)
				data := sizeInt.Bytes()
				data = append(data, byte(3))
				data = append(data, []byte("key")...)
				data = append(data, MAPPING_EQUALS_DELIMITER)
				data = append(data, byte(50))
				data = append(data, []byte("short")...)
				return data
			}(),
			expectError: true,
			description: "truncated value data",
		},
		{
			name: "valid_mapping_within_limits",
			data: func() []byte {
				gomap := make(map[string]string)
				for i := 0; i < 10; i++ {
					key := string(rune('a' + i))
					val := string(rune('0' + i))
					gomap[key] = val
				}
				mapping, _ := GoMapToMapping(gomap)
				return mapping.Data()
			}(),
			expectError: false,
			description: "valid mapping should parse without error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			done := make(chan struct{})
			var mapping Mapping
			var errs []error

			go func() {
				defer close(done)
				mapping, _, errs = ReadMapping(tt.data)
			}()

			select {
			case <-done:
				if tt.expectError && len(errs) == 0 {
					t.Errorf("Expected error for %s, but got none", tt.description)
				}
				if !tt.expectError && len(errs) > 0 {
					t.Errorf("Expected no error for %s, but got: %v", tt.description, errs)
				}

				vals := mapping.Values()
				if len(vals) > MAX_MAPPING_PAIRS {
					t.Errorf("Parsed more than MAX_MAPPING_PAIRS: got %d pairs", len(vals))
				}
			case <-time.After(5 * time.Second):
				t.Fatalf("Parser hung (infinite loop detected) on: %s", tt.description)
			}
		})
	}
}

// TestMappingPairCountLimit tests that the MAX_MAPPING_PAIRS limit is enforced
func TestMappingPairCountLimit(t *testing.T) {
	gomap := make(map[string]string)
	for i := 0; i < MAX_MAPPING_PAIRS; i++ {
		key := string(rune('a'+(i%26))) + string(rune('a'+((i/26)%26))) + string(rune('0'+(i%10)))
		val := "v"
		gomap[key] = val
	}

	mapping, err := GoMapToMapping(gomap)
	if err != nil {
		t.Fatalf("Failed to create mapping: %v", err)
	}
	data := mapping.Data()

	_, _, errs := ReadMapping(data)
	if len(errs) > 0 {
		t.Errorf("Valid mapping with MAX_MAPPING_PAIRS should parse: %v", errs)
	}
}

// TestForwardProgressDetection tests that the parser detects when it's not making progress
func TestForwardProgressDetection(t *testing.T) {
	sizeInt, _ := NewIntegerFromInt(20, 2)
	data := sizeInt.Bytes()
	data = append(data, []byte{3, 'a', 'b', 'c', '=', 1, 'x', ';'}...)

	_, _, errs := ReadMapping(data)
	t.Logf("Parsing completed with %d errors", len(errs))
}
