package data

import (
	"bytes"
	"testing"

	"github.com/samber/oops"
	"github.com/stretchr/testify/assert"
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

	assert.Equal(true, dups.HasDuplicateKeys(), "HasDuplicateKeys() did not report true when duplicate keys present")
}

func TestHasDuplicateKeysFalseWithoutDuplicates(t *testing.T) {
	assert := assert.New(t)

	mapping, _, _ := NewMapping([]byte{0x00, 0x06, 0x01, 0x61, 0x3d, 0x01, 0x62, 0x3b})

	assert.Equal(false, mapping.HasDuplicateKeys(), "HasDuplicateKeys() did not report false when no duplicate keys present")
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

	status := stopValueRead(oops.Errorf("error parsing string: zero length"))

	assert.Equal(true, status, "stopValueRead() did not return true when String error found")
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
