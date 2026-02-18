package data

import (
	"errors"
	"sort"

	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// MappingValues represents the parsed key value pairs inside of an I2P Mapping.
type MappingValues [][2]I2PString

// NewMappingValues creates a new empty MappingValues with optional initial capacity.
// This is the safe way to construct MappingValues for building mappings programmatically.
//
// Parameters:
//   - capacity: Optional initial capacity hint (0 for default)
//
// Returns:
//   - MappingValues: Empty mapping values ready for use
//
// Example:
//
//	mv := data.NewMappingValues(10) // Pre-allocate space for 10 pairs
//	mv, err := mv.Add("key1", "value1")
//	if err != nil {
//	    return err
//	}
func NewMappingValues(capacity int) MappingValues {
	if capacity < 0 {
		capacity = 0
	}
	log.WithFields(logger.Fields{
		"capacity": capacity,
	}).Debug("Creating new MappingValues")
	return make(MappingValues, 0, capacity)
}

// Add appends a new key-value pair to the MappingValues.
// Both key and value are validated as I2P strings before adding.
//
// Parameters:
//   - key: The key string (max 255 bytes)
//   - value: The value string (max 255 bytes)
//
// Returns:
//   - MappingValues: Updated mapping values with the new pair
//   - error: Error if key or value validation fails
//
// Example:
//
//	mv := data.NewMappingValues(0)
//	mv, err := mv.Add("host", "127.0.0.1")
//	if err != nil {
//	    return err
//	}
//	mv, err = mv.Add("port", "7654")
func (mv MappingValues) Add(key, value string) (MappingValues, error) {
	log.WithFields(logger.Fields{
		"key":   key,
		"value": value,
	}).Debug("Adding key-value pair to MappingValues")

	// Reject empty keys (keys must be non-empty for lookup)
	if key == "" {
		log.Error("Empty key not allowed in MappingValues")
		return mv, oops.Errorf("empty key not allowed")
	}
	// Empty values are allowed per I2P spec: "Length may be 0"

	// Validate and convert key
	keyStr, err := NewI2PString(key)
	if err != nil {
		log.WithFields(logger.Fields{
			"key":   key,
			"error": err,
		}).Error("Failed to create I2PString for key")
		return mv, oops.Wrapf(err, "invalid key: %s", key)
	}

	// Validate and convert value
	valStr, err := NewI2PString(value)
	if err != nil {
		log.WithFields(logger.Fields{
			"value": value,
			"error": err,
		}).Error("Failed to create I2PString for value")
		return mv, oops.Wrapf(err, "invalid value: %s", value)
	}

	log.WithFields(logger.Fields{
		"key":         key,
		"value":       value,
		"pairs_count": len(mv) + 1,
	}).Debug("Successfully added key-value pair")

	return append(mv, [2]I2PString{keyStr, valStr}), nil
}

// Validate checks if all key-value pairs in MappingValues are valid.
// This ensures all I2PStrings are properly formatted.
//
// Returns:
//   - error: Error if any key or value is invalid, nil otherwise
//
// Example:
//
//	if err := mv.Validate(); err != nil {
//	    return fmt.Errorf("invalid mapping values: %w", err)
//	}
func (mv MappingValues) Validate() error {
	log.WithFields(logger.Fields{
		"pairs_count": len(mv),
	}).Debug("Validating MappingValues")

	for i, pair := range mv {
		// Validate key
		if !pair[0].IsValid() {
			log.WithFields(logger.Fields{
				"index": i,
				"pair":  pair,
			}).Error("Invalid key in MappingValues")
			return oops.Errorf("invalid key at index %d", i)
		}

		// Validate value
		if !pair[1].IsValid() {
			log.WithFields(logger.Fields{
				"index": i,
				"pair":  pair,
			}).Error("Invalid value in MappingValues")
			return oops.Errorf("invalid value at index %d", i)
		}

		// Validate key can be extracted
		if _, err := pair[0].DataSafe(); err != nil {
			log.WithFields(logger.Fields{
				"index": i,
				"error": err,
			}).Error("Cannot extract key data")
			return oops.Wrapf(err, "cannot extract key at index %d", i)
		}

		// Validate value can be extracted
		if _, err := pair[1].DataSafe(); err != nil {
			log.WithFields(logger.Fields{
				"index": i,
				"error": err,
			}).Error("Cannot extract value data")
			return oops.Wrapf(err, "cannot extract value at index %d", i)
		}
	}

	log.Debug("MappingValues validation passed")
	return nil
}

// IsValid returns true if all key-value pairs in MappingValues are valid.
// This is a convenience wrapper around Validate().
//
// Example:
//
//	if !mv.IsValid() {
//	    return errors.New("invalid mapping values")
//	}
func (mv MappingValues) IsValid() bool {
	return mv.Validate() == nil
}

// Get retrieves the value for a given key from MappingValues.
func (m MappingValues) Get(key I2PString) I2PString {
	keyBytes, err := key.Data()
	if err != nil {
		log.WithError(err).Error("Failed to extract key data in MappingValues.Get()")
		return nil
	}
	log.WithFields(logger.Fields{
		"key": string(keyBytes),
	}).Debug("Searching for key in MappingValues")
	for _, pair := range m {
		kb, err := pair[0].Data()
		if err != nil {
			continue
		}
		if kb == keyBytes {
			log.WithFields(logger.Fields{
				"key":   string(keyBytes),
				"value": string(pair[1][1:]),
			}).Debug("Found matching key in MappingValues")
			return pair[1]
		}
	}
	log.WithFields(logger.Fields{
		"key": string(keyBytes),
	}).Debug("Key not found in MappingValues")
	return nil
}

// ValuesToMapping creates a *Mapping using MappingValues.
// The values are sorted in the order defined in mappingOrder.
// Returns error if the total mapping data exceeds the maximum size (65535 bytes).
func ValuesToMapping(values MappingValues) (*Mapping, error) {
	mappingOrder(values)

	// Default length to 2 * len
	// 1 byte for ';'
	// 1 byte for '='
	log.WithFields(logger.Fields{
		"values_count": len(values),
	}).Debug("Converting MappingValues to Mapping")
	baseLength := 2 * len(values)
	for _, mappingVals := range values {
		for _, keyOrVal := range mappingVals {
			baseLength += len(keyOrVal)
		}
	}

	if baseLength > MAX_MAPPING_DATA_SIZE {
		log.WithFields(logger.Fields{
			"mapping_size": baseLength,
			"max_size":     MAX_MAPPING_DATA_SIZE,
		}).Error("Mapping data exceeds maximum size")
		return nil, oops.Errorf("mapping data size %d exceeds maximum %d bytes", baseLength, MAX_MAPPING_DATA_SIZE)
	}

	log.WithFields(logger.Fields{
		"mapping_size": baseLength,
	}).Debug("Created Mapping from MappingValues")

	mappingSize, err := NewIntegerFromInt(baseLength, 2)
	if err != nil {
		log.WithError(err).Error("Failed to create mapping size integer")
		return nil, oops.Errorf("failed to encode mapping size: %w", err)
	}
	return &Mapping{
		size: mappingSize,
		vals: &values,
	}, nil
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
	log.WithFields(logger.Fields{
		"input_length": len(remainder),
		"map_length":   map_length.Int(),
	}).Debug("Reading MappingValues")

	if err := validateMappingInput(remainder); err != nil {
		errs = []error{err}
		return
	}

	map_values := make(MappingValues, 0)
	if errs = validateMappingLength(remainder, map_length); len(errs) > 0 {
		log.WithFields(logger.Fields{
			"error_count": len(errs),
		}).Warn("Mapping length validation warnings")
	}

	var remainder_updated []byte
	remainder_updated, map_values, errs = parseKeyValuePairs(remainder, map_values, errs)
	values = &map_values

	log.WithFields(logger.Fields{
		"values_count":     len(map_values),
		"remainder_length": len(remainder_updated),
		"error_count":      len(errs),
	}).Debug("Finished reading MappingValues")

	return
}

// validateMappingInput checks if the input data is valid for mapping parsing.
func validateMappingInput(remainder []byte) error {
	if len(remainder) < 1 {
		log.WithFields(logger.Fields{
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
		log.WithFields(logger.Fields{
			"at":                   "(Mapping) Values",
			"mapping_bytes_length": mapping_len,
			"mapping_length_field": int_map_length,
			"reason":               "data longer than expected",
		}).Warn("mapping format warning")
		errs = append(errs, oops.Errorf("warning parsing mapping: data exists beyond length of mapping"))
	} else if int_map_length > mapping_len {
		log.WithFields(logger.Fields{
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
	pairCount := 0
	previousLength := len(remainder)

	for {
		if shouldStopLoop(pairCount, remainder, previousLength) {
			if pairCount >= MAX_MAPPING_PAIRS {
				errs = append(errs, oops.Errorf("exceeded maximum mapping pairs (%d)", MAX_MAPPING_PAIRS))
			}
			break
		}

		if err := checkForwardProgress(pairCount, len(remainder), previousLength); err != nil {
			errs = append(errs, err)
			break
		}
		previousLength = len(remainder)

		var keyValuePair [2]I2PString
		var err error

		remainder, keyValuePair, err = parseSingleKeyValuePair(remainder, encounteredKeysMap)
		if err != nil {
			errs = append(errs, err)
			if shouldStopParsing(err) {
				break
			}
		}

		map_values = append(map_values, keyValuePair)
		pairCount++
		if len(remainder) == 0 {
			break
		}

		storeEncounteredKey(keyValuePair[0], encounteredKeysMap)
	}

	log.WithFields(logger.Fields{
		"at":              "(Mapping) Values",
		"pairs_parsed":    pairCount,
		"errors":          len(errs),
		"remainder_bytes": len(remainder),
	}).Debug("Completed parsing key-value pairs")

	return remainder, map_values, errs
}

// shouldStopLoop checks whether the parsing loop should terminate due to
// exceeding the maximum pair count or insufficient data.
func shouldStopLoop(pairCount int, remainder []byte, previousLength int) bool {
	if pairCount >= MAX_MAPPING_PAIRS {
		log.WithFields(logger.Fields{
			"at":         "(Mapping) Values",
			"pair_count": pairCount,
			"max_pairs":  MAX_MAPPING_PAIRS,
			"reason":     "exceeded maximum mapping pairs",
		}).Error("mapping format violation")
		return true
	}
	return !hasMinimumBytesForKeyValuePair(remainder)
}

// checkForwardProgress detects infinite loops by verifying the parser consumes bytes
// on each iteration after the first pair.
func checkForwardProgress(pairCount int, currentLength int, previousLength int) error {
	if currentLength >= previousLength && pairCount > 0 {
		log.WithFields(logger.Fields{
			"at":              "(Mapping) Values",
			"pair_count":      pairCount,
			"current_length":  currentLength,
			"previous_length": previousLength,
			"reason":          "no forward progress in parsing",
		}).Error("mapping format violation - infinite loop detected")
		return oops.Errorf("no forward progress in parsing mapping (infinite loop detected)")
	}
	return nil
}

// parseSingleKeyValuePair extracts one complete key-value pair from the remainder data.
func parseSingleKeyValuePair(remainder []byte, encounteredKeysMap map[string]bool) ([]byte, [2]I2PString, error) {
	var keyValuePair [2]I2PString
	var accumulatedErrors []error

	// Parse key
	remainder, key_str, err := parseAndValidateKey(remainder, encounteredKeysMap)
	if err != nil {
		accumulatedErrors = append(accumulatedErrors, err)
	}
	keyValuePair[0] = key_str

	// Parse equals delimiter
	remainder, err = validateAndConsumeDelimiter(remainder, 0x3d, "=")
	if err != nil {
		// Delimiter errors are critical, return immediately
		return remainder, keyValuePair, err
	}

	// Parse value
	remainder, val_str, err := parseAndValidateValue(remainder)
	if err != nil {
		accumulatedErrors = append(accumulatedErrors, err)
	}
	keyValuePair[1] = val_str

	// Parse semicolon delimiter
	remainder, err = validateAndConsumeDelimiter(remainder, 0x3b, ";")
	if err != nil {
		// Delimiter errors are critical, return immediately
		return remainder, keyValuePair, err
	}

	// Return the first accumulated error if any, but still return the parsed data
	if len(accumulatedErrors) > 0 {
		return remainder, keyValuePair, accumulatedErrors[0]
	}

	return remainder, keyValuePair, nil
}

// parseAndValidateKey extracts a key string and validates it for duplicates.
func parseAndValidateKey(remainder []byte, encounteredKeysMap map[string]bool) ([]byte, I2PString, error) {
	remainder, key_str, err := parseKeyFromRemainder(remainder)

	// Check for string parsing errors that should stop value reading
	if err != nil && stopValueRead(err) {
		return remainder, key_str, err
	}

	// Check for duplicate keys (this generates an error but doesn't stop parsing)
	if dupErr := checkForDuplicateKey(key_str, encounteredKeysMap); dupErr != nil {
		return remainder, key_str, dupErr
	}

	return remainder, key_str, err
}

// parseAndValidateValue extracts a value string from the remainder data.
func parseAndValidateValue(remainder []byte) ([]byte, I2PString, error) {
	remainder, val_str, err := parseValueFromRemainder(remainder)

	// Check for string parsing errors that should stop value reading
	if err != nil && stopValueRead(err) {
		return remainder, val_str, err
	}

	return remainder, val_str, err
}

// shouldStopParsing determines if parsing should halt based on the error type.
func shouldStopParsing(err error) bool {
	// Stop parsing on delimiter validation errors which indicate format corruption
	return errors.Is(err, ErrMappingExpectedEquals) || errors.Is(err, ErrMappingExpectedSemicolon)
}

// hasMinimumBytesForKeyValuePair checks if there are enough bytes for another key-value pair.
func hasMinimumBytesForKeyValuePair(remainder []byte) bool {
	// Minimum byte length required: 2 bytes for each string length,
	// at least 1 byte per string, one byte for =, one byte for ;
	if len(remainder) < 6 {
		log.WithFields(logger.Fields{
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
		log.WithFields(logger.Fields{
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
		log.WithFields(logger.Fields{
			"at":     "(Mapping) Values",
			"reason": "expected " + delimiterName,
			"value:": string(remainder),
		}).Warn("mapping format violation")
		log.Printf("ERRVAL: %s", remainder)
		if delimiter == MAPPING_EQUALS_DELIMITER {
			return remainder, ErrMappingExpectedEquals
		}
		return remainder, ErrMappingExpectedSemicolon
	}
	return remainder[1:], nil
}

// storeEncounteredKey records that a key has been seen in the current mapping.
func storeEncounteredKey(key_str I2PString, encounteredKeysMap map[string]bool) {
	keyBytes, _ := key_str.Data()
	keyAsString := string(keyBytes)
	encounteredKeysMap[keyAsString] = true
}
