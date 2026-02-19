package data

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
