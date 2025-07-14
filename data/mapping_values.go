package data

import (
	"sort"

	"github.com/samber/oops"
	"github.com/sirupsen/logrus"
)

// MappingValues represents the parsed key value pairs inside of an I2P Mapping.
type MappingValues [][2]I2PString

// Get retrieves the value for a given key from MappingValues.
func (m MappingValues) Get(key I2PString) I2PString {
	keyBytes, _ := key.Data()
	log.WithFields(logrus.Fields{
		"key": string(keyBytes),
	}).Debug("Searching for key in MappingValues")
	for _, pair := range m {
		kb, _ := pair[0][0:].Data()
		if kb == keyBytes {
			log.WithFields(logrus.Fields{
				"key":   string(keyBytes),
				"value": string(pair[1][1:]),
			}).Debug("Found matching key in MappingValues")
			return pair[1]
		}
	}
	log.WithFields(logrus.Fields{
		"key": string(keyBytes),
	}).Debug("Key not found in MappingValues")
	return nil
}

// ValuesToMapping creates a *Mapping using MappingValues.
// The values are sorted in the order defined in mappingOrder.
func ValuesToMapping(values MappingValues) *Mapping {
	mappingOrder(values)

	// Default length to 2 * len
	// 1 byte for ';'
	// 1 byte for '='
	log.WithFields(logrus.Fields{
		"values_count": len(values),
	}).Debug("Converting MappingValues to Mapping")
	baseLength := 2 * len(values)
	for _, mappingVals := range values {
		for _, keyOrVal := range mappingVals {
			baseLength += len(keyOrVal)
		}
	}

	log.WithFields(logrus.Fields{
		"mapping_size": baseLength,
	}).Debug("Created Mapping from MappingValues")

	mappingSize, _ := NewIntegerFromInt(baseLength, 2)
	return &Mapping{
		size: mappingSize,
		vals: &values,
	}
}

// I2P Mappings require consistent order in some cases for cryptographic signing, and sorting
// by keys. The Mapping is sorted lexographically by keys. Duplicate keys are allowed in general,
// but in implementations where they must be sorted like I2CP SessionConfig duplicate keys are not allowed.
// In practice routers do not seem to allow duplicate keys.
func mappingOrder(values MappingValues) {
	sort.SliceStable(values, func(i, j int) bool {
		// Lexographic sort on keys only
		data1, _ := values[i][0].Data()
		data2, _ := values[j][0].Data()
		return data1 < data2
	})
}

// ReadMappingValues returns *MappingValues from a []byte.
// The remaining bytes after the specified length are also returned.
// Returns a list of errors that occurred during parsing.
func ReadMappingValues(remainder []byte, map_length Integer) (values *MappingValues, remainder_bytes []byte, errs []error) {
	log.WithFields(logrus.Fields{
		"input_length": len(remainder),
		"map_length":   map_length.Int(),
	}).Debug("Reading MappingValues")

	if err := validateMappingInput(remainder); err != nil {
		errs = []error{err}
		return
	}

	map_values := make(MappingValues, 0)
	if errs = validateMappingLength(remainder, map_length); len(errs) > 0 {
		log.WithFields(logrus.Fields{
			"error_count": len(errs),
		}).Warn("Mapping length validation warnings")
	}

	var remainder_updated []byte
	remainder_updated, map_values, errs = parseKeyValuePairs(remainder, map_values, errs)
	values = &map_values

	log.WithFields(logrus.Fields{
		"values_count":     len(map_values),
		"remainder_length": len(remainder_updated),
		"error_count":      len(errs),
	}).Debug("Finished reading MappingValues")

	return
}

// validateMappingInput checks if the input data is valid for mapping parsing.
func validateMappingInput(remainder []byte) error {
	if len(remainder) < 1 {
		log.WithFields(logrus.Fields{
			"at":     "(Mapping) Values",
			"reason": "data shorter than expected",
		}).Error("mapping contained no data")
		return oops.Errorf("mapping contained no data")
	}
	return nil
}

// validateMappingLength validates the expected mapping length against actual data length.
func validateMappingLength(remainder []byte, map_length Integer) []error {
	var errs []error
	int_map_length := map_length.Int()
	mapping_len := len(remainder)

	if mapping_len > int_map_length {
		log.WithFields(logrus.Fields{
			"at":                   "(Mapping) Values",
			"mapping_bytes_length": mapping_len,
			"mapping_length_field": int_map_length,
			"reason":               "data longer than expected",
		}).Warn("mapping format warning")
		errs = append(errs, oops.Errorf("warning parsing mapping: data exists beyond length of mapping"))
	} else if int_map_length > mapping_len {
		log.WithFields(logrus.Fields{
			"at":                   "(Mapping) Values",
			"mapping_bytes_length": mapping_len,
			"mapping_length_field": int_map_length,
			"reason":               "data shorter than expected",
		}).Warn("mapping format warning")
		errs = append(errs, oops.Errorf("warning parsing mapping: mapping length exceeds provided data"))
	}

	return errs
}

// parseKeyValuePairs iterates through the remainder data parsing key-value pairs.
func parseKeyValuePairs(remainder []byte, map_values MappingValues, errs []error) ([]byte, MappingValues, []error) {
	encounteredKeysMap := map[string]bool{}

	for {
		if !hasMinimumBytesForKeyValuePair(remainder) {
			break
		}

		var key_str, val_str I2PString
		var err error

		remainder, key_str, err = parseKeyFromRemainder(remainder)
		if err != nil {
			if stopValueRead(err) {
				errs = append(errs, err)
			}
		}

		if err := checkForDuplicateKey(key_str, encounteredKeysMap); err != nil {
			errs = append(errs, err)
		}

		remainder, err = validateAndConsumeDelimiter(remainder, 0x3d, "=")
		if err != nil {
			errs = append(errs, err)
			break
		}

		remainder, val_str, err = parseValueFromRemainder(remainder)
		if err != nil {
			if stopValueRead(err) {
				errs = append(errs, err)
			}
		}

		remainder, err = validateAndConsumeDelimiter(remainder, 0x3b, ";")
		if err != nil {
			errs = append(errs, err)
			break
		}

		map_values = append(map_values, [2]I2PString{key_str, val_str})
		if len(remainder) == 0 {
			break
		}

		storeEncounteredKey(key_str, encounteredKeysMap)
	}

	return remainder, map_values, errs
}

// hasMinimumBytesForKeyValuePair checks if there are enough bytes for another key-value pair.
func hasMinimumBytesForKeyValuePair(remainder []byte) bool {
	// Minimum byte length required: 2 bytes for each string length,
	// at least 1 byte per string, one byte for =, one byte for ;
	if len(remainder) < 6 {
		log.WithFields(logrus.Fields{
			"at":     "(Mapping) Values",
			"reason": "mapping format violation",
		}).Warn("mapping format violation, too few bytes for a kv pair")
		return false
	}
	return true
}

// parseKeyFromRemainder extracts a key string from the remainder data.
func parseKeyFromRemainder(remainder []byte) ([]byte, I2PString, error) {
	key_str, more, err := ReadI2PString(remainder)
	return more, key_str, err
}

// parseValueFromRemainder extracts a value string from the remainder data.
func parseValueFromRemainder(remainder []byte) ([]byte, I2PString, error) {
	val_str, more, err := ReadI2PString(remainder)
	return more, val_str, err
}

// checkForDuplicateKey validates that a key hasn't been encountered before in this mapping.
func checkForDuplicateKey(key_str I2PString, encounteredKeysMap map[string]bool) error {
	keyBytes, _ := key_str.Data()
	keyAsString := string(keyBytes)
	_, ok := encounteredKeysMap[keyAsString]
	if ok {
		log.WithFields(logrus.Fields{
			"at":     "(Mapping) Values",
			"reason": "duplicate key in mapping",
			"key":    string(key_str),
		}).Error("mapping format violation")
		log.Printf("DUPE: %s", key_str)
		return oops.Errorf("mapping format violation, duplicate key in mapping")
	}
	return nil
}

// validateAndConsumeDelimiter checks for the expected delimiter and consumes it from remainder.
func validateAndConsumeDelimiter(remainder []byte, delimiter byte, delimiterName string) ([]byte, error) {
	if !beginsWith(remainder, delimiter) {
		log.WithFields(logrus.Fields{
			"at":     "(Mapping) Values",
			"reason": "expected " + delimiterName,
			"value:": string(remainder),
		}).Warn("mapping format violation")
		log.Printf("ERRVAL: %s", remainder)
		return remainder, oops.Errorf("mapping format violation, expected %s", delimiterName)
	}
	return remainder[1:], nil
}

// storeEncounteredKey records that a key has been seen in the current mapping.
func storeEncounteredKey(key_str I2PString, encounteredKeysMap map[string]bool) {
	keyBytes, _ := key_str.Data()
	keyAsString := string(keyBytes)
	encounteredKeysMap[keyAsString] = true
}
