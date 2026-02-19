package data

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

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
		invalidKey := I2PString{10, 'a'}
		validValue, _ := NewI2PString("value")
		mv := MappingValues{
			[2]I2PString{invalidKey, validValue},
		}
		assert.False(t, mv.IsValid(), "invalid MappingValues should return false")
	})
}
