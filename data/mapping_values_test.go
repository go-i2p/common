package data

import (
	"fmt"
	"testing"
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
