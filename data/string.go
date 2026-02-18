package data

import (
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

/*
[I2P String]
Accurate for version 0.9.67

Description
Represents a UTF-8 encoded string.

Contents
1 or more bytes where the first byte is the number of bytes (not characters!) in the string
and the remaining 0-255 bytes are the non-null terminated UTF-8 encoded character array.
Length limit is 255 bytes (not characters). Length may be 0.
*/

// I2PString is the representation of an I2P String.
//
// https://geti2p.net/spec/common-structures#string
type I2PString []byte

// IsValid checks if the I2PString has a valid structure.
// Returns true if the length byte matches the actual data length.
func (str I2PString) IsValid() bool {
	if len(str) == 0 {
		return false
	}
	declaredLen := int(str[0])
	return len(str) == declaredLen+1 && declaredLen <= STRING_MAX_SIZE
}

// DataSafe returns the I2PString content with strict validation.
// Unlike Data(), this fails fast on any inconsistency.
// Returns error if the I2PString structure is invalid.
func (str I2PString) DataSafe() (string, error) {
	if !str.IsValid() {
		log.WithFields(logger.Fields{
			"at":     "(I2PString) DataSafe",
			"reason": "invalid I2PString structure",
		}).Error("invalid I2PString structure")
		return "", oops.Errorf("invalid I2PString structure")
	}
	// At this point we know the structure is valid
	length := int(str[0])
	if length == 0 {
		log.Debug("I2PString is empty (valid zero-length string)")
		return "", nil
	}
	data := string(str[1 : length+1])
	return data, nil
}

// Length returns the length specified in the first byte.
// Returns error if the specified does not match the actual length or the string is otherwise invalid.
func (str I2PString) Length() (length int, err error) {
	if len(str) == 0 {
		log.WithFields(logger.Fields{
			"at":     "(I2PString) Length",
			"reason": "no data",
		}).Error("error parsing string")
		err = ErrZeroLength
		return
	}
	l, _, err := NewInteger(str[:], 1)
	if err != nil {
		log.WithError(err).Error("Failed to create Integer from I2PString")
		return l.Int(), err
	}
	length = l.Int()
	str_len := len(str)

	if length > (str_len - 1) {
		log.WithFields(logger.Fields{
			"at":                  "(I2PString) Length",
			"string_bytes_length": str_len,
			"string_length_field": length,
			"reason":              "data less than specified by length",
		}).Warn("string format warning")
		err = ErrDataTooShort
	}

	if (str_len - 1) > length {
		log.WithFields(logger.Fields{
			"at":                  "(I2PString) Length",
			"string_bytes_length": str_len,
			"string_length_field": length,
			"reason":              "data contains extra bytes beyond specified length",
		}).Warn("string format warning")
		err = ErrDataTooLong
	}

	return
}

// Data returns the I2PString content as a string trimmed to the specified length and not including the length byte.
// Returns error encountered by Length.
func (str I2PString) Data() (data string, err error) {
	length, err := str.Length()
	if err != nil {
		switch err {
		case ErrZeroLength:
			log.WithError(err).Warn("Zero length I2PString")
			return "", err
		case ErrDataTooShort:
			log.WithError(err).Warn("I2PString data shorter than specified length")
			/*
				if is, e := ToI2PString(string(str[:])); e != nil {
					log.WithError(e).Error("Failed to convert short I2PString")
					return "", e
				} else {
					return is.Data()
				}
			*/ //Recovery attempt
			return "", err
		case ErrDataTooLong:
			log.WithError(err).Warn("I2PString contains data beyond specified length")
			return "", err
		default:
			log.WithError(err).Error("Unknown error encountered in I2PString.Data()")
			return "", err
		}
	}
	if length == 0 {
		log.Debug("I2PString is empty")
		return "", nil
	}
	data = string(str[1 : length+1])
	return data, nil
}

// NewI2PString creates a validated I2PString from a Go string.
// Returns error if the string exceeds STRING_MAX_SIZE (255 bytes).
// This is the preferred constructor for creating I2PStrings from Go strings.
func NewI2PString(content string) (I2PString, error) {
	log.WithFields(logger.Fields{
		"input_length": len(content),
	}).Debug("Creating new I2PString from string")
	if len(content) > STRING_MAX_SIZE {
		log.WithFields(logger.Fields{
			"at":         "NewI2PString",
			"string_len": len(content),
			"max_len":    STRING_MAX_SIZE,
			"reason":     "string too long",
		}).Error("cannot create I2P string")
		return nil, oops.Errorf("string too long: %d bytes (max %d)",
			len(content), STRING_MAX_SIZE)
	}
	result := make(I2PString, 1+len(content))
	result[0] = byte(len(content))
	copy(result[1:], content)
	return result, nil
}

// NewI2PStringFromBytes creates an I2PString from raw bytes with validation.
// Validates that the length prefix matches the actual data length.
// This is the preferred constructor for creating I2PStrings from byte slices.
func NewI2PStringFromBytes(data []byte) (I2PString, error) {
	log.WithFields(logger.Fields{
		"input_length": len(data),
	}).Debug("Creating I2PString from bytes")
	if len(data) == 0 {
		log.Error("I2PString data cannot be empty")
		return nil, oops.Errorf("I2PString data cannot be empty")
	}
	declaredLen := int(data[0])
	if len(data) != declaredLen+1 {
		log.WithFields(logger.Fields{
			"at":           "NewI2PStringFromBytes",
			"declared_len": declaredLen,
			"actual_len":   len(data) - 1,
			"reason":       "length mismatch",
		}).Error("I2PString length mismatch")
		return nil, oops.Errorf("I2PString length mismatch: declared %d, actual %d",
			declaredLen, len(data)-1)
	}
	if declaredLen > STRING_MAX_SIZE {
		log.WithFields(logger.Fields{
			"at":           "NewI2PStringFromBytes",
			"declared_len": declaredLen,
			"max_len":      STRING_MAX_SIZE,
			"reason":       "string too long",
		}).Error("I2PString too long")
		return nil, oops.Errorf("I2PString too long: %d bytes (max %d)",
			declaredLen, STRING_MAX_SIZE)
	}
	result := make(I2PString, len(data))
	copy(result, data)
	return result, nil
}

// ToI2PString converts a Go string to an I2PString.
// Returns error if the string exceeds STRING_MAX_SIZE.
// Deprecated: Use NewI2PString instead for better clarity and consistency.
func ToI2PString(data string) (str I2PString, err error) {
	log.WithFields(logger.Fields{
		"input_length": len(data),
	}).Debug("Converting string to I2PString")
	data_len := len(data)
	if data_len > STRING_MAX_SIZE {
		log.WithFields(logger.Fields{
			"at":         "ToI2PI2PString",
			"string_len": data_len,
			"max_len":    STRING_MAX_SIZE,
			"reason":     "too much data",
		}).Error("cannot create I2P string")
		err = oops.Errorf("cannot store that much data in I2P string")
		return
	}
	i2p_string := []byte{byte(data_len)}
	i2p_string = append(i2p_string, []byte(data)...)
	str = I2PString(i2p_string)
	return
}

// ReadI2PString returns I2PString from a []byte.
// The remaining bytes after the specified length are also returned.
// Returns a list of errors that occurred during parsing.
func ReadI2PString(data []byte) (str I2PString, remainder []byte, err error) {
	if err = validateI2PStringData(data); err != nil {
		return
	}

	log.WithFields(logger.Fields{
		"input_length": len(data),
	}).Debug("Reading I2PString from bytes")

	length, err := parseI2PStringLength(data)
	if err != nil {
		return
	}

	if err = validateI2PStringDataLength(data, length); err != nil {
		str = data
		remainder = nil
		return
	}

	str, remainder = extractI2PStringData(data, length)

	if err = verifyI2PStringLength(str, length); err != nil {
		return
	}
	return
}

// validateI2PStringData validates that data is not empty.
// Returns error if data has zero length.
func validateI2PStringData(data []byte) error {
	if len(data) == 0 {
		err := ErrZeroLength
		log.WithError(err).Error("Passed data with len == 0")
		return err
	}
	return nil
}

// parseI2PStringLength parses the length field from the I2PString data.
// Returns the length value and any error encountered during parsing.
func parseI2PStringLength(data []byte) (int, error) {
	length, _, err := NewInteger(data, 1)
	if err != nil {
		log.WithError(err).Error("Failed to read I2PString length")
		return 0, err
	}
	return length.Int(), nil
}

// validateI2PStringDataLength validates that sufficient data exists for the specified string length.
// Returns error if data is too short for the specified length.
func validateI2PStringDataLength(data []byte, length int) error {
	data_len := length + 1
	if data_len > len(data) {
		log.Errorf("I2PString length %d exceeds available data %d", length, len(data)-1)
		err := ErrDataTooShort
		log.WithError(err).Error("Failed to read I2PString")
		return err
	}
	return nil
}

// extractI2PStringData extracts the I2PString and remainder from data.
// Returns the string bytes and remaining data after extraction.
func extractI2PStringData(data []byte, length int) (I2PString, []byte) {
	data_len := length + 1
	str := data[:data_len]
	remainder := data[data_len:]
	return str, remainder
}

// verifyI2PStringLength verifies that the extracted string's actual byte count
// matches the declared length field (first byte).
// Returns error if there is a length mismatch.
func verifyI2PStringLength(str I2PString, expectedLength int) error {
	if len(str) == 0 {
		return ErrZeroLength
	}
	// The actual data bytes are everything after the length prefix byte.
	actualDataLen := len(str) - 1
	if actualDataLen != expectedLength {
		log.WithFields(logger.Fields{
			"expected_length": expectedLength,
			"actual_data_len": actualDataLen,
		}).Error("I2PString length mismatch")
		return ErrLengthMismatch
	}
	return nil
}
