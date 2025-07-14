package data

import (
	"github.com/samber/oops"
	"github.com/sirupsen/logrus"
)

/*
[I2P Mapping]
Accurate for version 0.9.49

Description
A set of key/value mappings or properties


Contents
A 2-byte size Integer followed by a series of String=String; pairs

+----+----+----+----+----+----+----+----+
|  size   |key_string (len + data) | =  |
+----+----+----+----+----+----+----+----+
| val_string (len + data)     | ;  | ...
+----+----+----+----+----+----+----+
size :: Integer
        length -> 2 bytes
        Total number of bytes that follow

key_string :: String
              A string (one byte length followed by UTF-8 encoded characters)

= :: A single byte containing '='

val_string :: String
              A string (one byte length followed by UTF-8 encoded characters)

; :: A single byte containing ';'
*/

// Mapping is the represenation of an I2P Mapping.
//
// https://geti2p.net/spec/common-structures#mapping
type Mapping struct {
	size *Integer
	vals *MappingValues
}

// Values returns the values contained in a Mapping as MappingValues.
func (mapping Mapping) Values() MappingValues {
	if mapping.vals == nil {
		log.Debug("Mapping values are nil, returning empty MappingValues")
		return MappingValues{}
	}
	log.WithFields(logrus.Fields{
		"values_count": len(*mapping.vals),
	}).Debug("Retrieved Mapping values")
	return *mapping.vals
}

// Data returns a Mapping in its []byte form.
func (mapping *Mapping) Data() []byte {
	bytes := mapping.size.Bytes()
	for _, pair := range mapping.Values() {
		klen, _ := pair[0].Length()
		keylen, _ := NewIntegerFromInt(klen, KEY_VAL_INTEGER_LENGTH)
		bytes = append(bytes, keylen.Bytes()...)
		bytes = append(bytes, pair[0][1:]...)
		bytes = append(bytes, MAPPING_EQUALS_DELIMITER)
		vlen, _ := pair[1].Length()
		vallen, _ := NewIntegerFromInt(vlen, KEY_VAL_INTEGER_LENGTH)
		bytes = append(bytes, vallen.Bytes()...)
		bytes = append(bytes, pair[1][1:]...)
		bytes = append(bytes, MAPPING_SEMICOLON_DELIMITER)
	}
	return bytes
}

// HasDuplicateKeys returns true if two keys in a mapping are identical.
func (mapping *Mapping) HasDuplicateKeys() bool {
	log.Debug("Checking for duplicate keys in Mapping")
	seen_values := make(map[string]bool)
	values := mapping.Values()
	for _, pair := range values {
		key, _ := pair[0].Data()
		if _, present := seen_values[key]; present {
			log.WithFields(logrus.Fields{
				"duplicate_key": key,
			}).Warn("Found duplicate key in Mapping")
			return true
		} else {
			seen_values[key] = true
		}
	}
	log.Debug("No duplicate keys found in Mapping")
	return false
}

// GoMapToMapping converts a Go map of unformatted strings to *Mapping.
func GoMapToMapping(gomap map[string]string) (mapping *Mapping, err error) {
	log.WithFields(logrus.Fields{
		"input_map_size": len(gomap),
	}).Debug("Converting Go map to Mapping")
	map_vals := MappingValues{}
	for k, v := range gomap {
		key_str, kerr := ToI2PString(k)
		if kerr != nil {
			log.WithError(kerr).Error("Failed to convert key to I2PString")
			err = kerr
			return
		}
		val_str, verr := ToI2PString(v)
		if verr != nil {
			log.WithError(verr).Error("Failed to convert value to I2PString")
			err = verr
			return
		}
		map_vals = append(
			map_vals,
			[2]I2PString{key_str, val_str},
		)
	}
	mapping = ValuesToMapping(map_vals)
	log.WithFields(logrus.Fields{
		"mapping_size": len(map_vals),
	}).Debug("Successfully converted Go map to Mapping")
	return
}

// ReadMapping returns Mapping from a []byte.
// The remaining bytes after the specified length are also returned.
// Returns a list of errors that occurred during parsing.
func ReadMapping(bytes []byte) (mapping Mapping, remainder []byte, err []error) {
	log.WithFields(logrus.Fields{
		"input_length": len(bytes),
	}).Debug("Reading Mapping from bytes")

	if inputValidationErr := validateMappingInputData(bytes); inputValidationErr != nil {
		err = append(err, inputValidationErr)
		return
	}

	size, remainder, sizeErr := parseMappingSize(bytes)
	if sizeErr != nil {
		err = append(err, sizeErr)
	}
	mapping.size = size

	if size.Int() == 0 {
		log.Warn("Mapping size is zero")
		return
	}

	return processMappingData(mapping, remainder, size, err)
}

// validateMappingInputData checks if the input data meets minimum requirements.
func validateMappingInputData(bytes []byte) error {
	if len(bytes) < MAPPING_MIN_SIZE {
		log.WithFields(logrus.Fields{
			"at":     "ReadMapping",
			"reason": "zero length",
		}).Warn("mapping format violation")
		return oops.Errorf("zero length")
	}
	return nil
}

// parseMappingSize extracts the size field from the beginning of the mapping data.
func parseMappingSize(bytes []byte) (*Integer, []byte, error) {
	size, remainder, err := NewInteger(bytes, MAPPING_SIZE_FIELD_LENGTH)
	if err != nil {
		log.WithError(err).Error("Failed to read Mapping size")
	}
	return size, remainder, err
}

// processMappingData handles the main data processing logic with length validation.
func processMappingData(mapping Mapping, remainder []byte, size *Integer, err []error) (Mapping, []byte, []error) {
	if len(remainder) < size.Int() {
		return handleInsufficientData(mapping, remainder, size, err)
	}

	return processNormalMappingData(mapping, remainder, size, err)
}

// handleInsufficientData processes mapping when there's insufficient data for the declared size.
func handleInsufficientData(mapping Mapping, remainder []byte, size *Integer, err []error) (Mapping, []byte, []error) {
	log.WithFields(logrus.Fields{
		"expected_size": size.Int(),
		"actual_size":   len(remainder),
	}).Warn("mapping format violation: mapping length exceeds provided data")

	e := oops.Errorf("warning parsing mapping: mapping length exceeds provided data")
	err = append(err, e)

	// Use whatever data is available (recovery)
	map_bytes := remainder
	remainder = nil

	vals, _, mappingValueErrs := ReadMappingValues(map_bytes, *size)
	err = append(err, mappingValueErrs...)
	mapping.vals = vals
	return mapping, remainder, err
}

// processNormalMappingData handles the standard case where sufficient data is available.
func processNormalMappingData(mapping Mapping, remainder []byte, size *Integer, err []error) (Mapping, []byte, []error) {
	// Proceed normally if enough data is present
	map_bytes := remainder[:size.Int()]
	remainder = remainder[size.Int():]

	vals, _, mappingValueErrs := ReadMappingValues(map_bytes, *size)
	err = append(err, mappingValueErrs...)
	mapping.vals = vals

	if len(mappingValueErrs) > 0 {
		err = logAndAppendMappingValueErrors(err)
	}

	if len(remainder) > 0 {
		err = handleExtraDataBeyondMapping(remainder, size, err)
	}

	logMappingCompletionDetails(mapping, remainder, err)
	return mapping, remainder, err
}

// logAndAppendMappingValueErrors logs and appends errors from mapping value parsing.
func logAndAppendMappingValueErrors(err []error) []error {
	log.WithFields(logrus.Fields{
		"at":     "ReadMapping",
		"reason": "error parsing mapping values",
	}).Warn("mapping format violation")

	e := oops.Errorf("error parsing mapping values")
	return append(err, e)
}

// handleExtraDataBeyondMapping processes cases where extra bytes exist beyond the mapping length.
func handleExtraDataBeyondMapping(remainder []byte, size *Integer, err []error) []error {
	log.WithFields(logrus.Fields{
		"expected_size": size.Int(),
		"actual_size":   len(remainder),
	}).Error("mapping format violation: data exists beyond length of mapping")

	e := oops.Errorf("warning parsing mapping: data exists beyond length of mapping")
	return append(err, e)
}

// logMappingCompletionDetails logs detailed information about the completed mapping parsing.
func logMappingCompletionDetails(mapping Mapping, remainder []byte, err []error) {
	log.WithFields(logrus.Fields{
		"mapping_size":     mapping.size.Int(),
		"values_count":     len(*mapping.vals),
		"remainder_length": len(remainder),
		"error_count":      len(err),
	}).Debug("Finished reading Mapping")
}

// NewMapping creates a new *Mapping from []byte using ReadMapping.
// Returns a pointer to Mapping unlike ReadMapping.
func NewMapping(bytes []byte) (values *Mapping, remainder []byte, err []error) {
	log.WithFields(logrus.Fields{
		"input_length": len(bytes),
	}).Debug("Creating new Mapping")

	objvalues, remainder, err := ReadMapping(bytes)
	values = &objvalues

	log.WithFields(logrus.Fields{
		"values_count":     len(values.Values()),
		"remainder_length": len(remainder),
		"error_count":      len(err),
	}).Debug("Finished creating new Mapping")
	return
}
