package data

import (
	"github.com/samber/oops"
	"github.com/sirupsen/logrus"
)

/*
[I2P String]
Accurate for version 0.9.49

Description
Represents a UTF-8 encoded string.

Contents
1 or more bytes where the first byte is the number of bytes (not characters!) in the string
and the remaining 0-255 bytes are the non-null terminated UTF-8 encoded character array.
Length limit is 255 bytes (not characters). Length may be 0.
*/

// I2PString is the represenation of an I2P String.
//
// https://geti2p.net/spec/common-structures#string
type I2PString []byte

// Length returns the length specified in the first byte.
// Returns error if the specified does not match the actual length or the string is otherwise invalid.
func (str I2PString) Length() (length int, err error) {
	if len(str) == 0 {
		log.WithFields(logrus.Fields{
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
		log.WithFields(logrus.Fields{
			"at":                  "(I2PString) Length",
			"string_bytes_length": str_len,
			"string_length_field": length,
			"reason":              "data less than specified by length",
		}).Warn("string format warning")
		err = ErrDataTooShort
	}

	if (str_len - 1) > length {
		log.WithFields(logrus.Fields{
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
			data = string(str[1:])
			// data = string(str[1 : length+1]) // Should we recover and trim?
			return
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
	log.WithFields(logrus.Fields{
		"data_length": len(data),
	}).Debug("Retrieved I2PString data")
	return data, nil
}

// ToI2PString converts a Go string to an I2PString.
// Returns error if the string exceeds STRING_MAX_SIZE.
func ToI2PString(data string) (str I2PString, err error) {
	log.WithFields(logrus.Fields{
		"input_length": len(data),
	}).Debug("Converting string to I2PString")
	data_len := len(data)
	if data_len > STRING_MAX_SIZE {
		log.WithFields(logrus.Fields{
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
	log.WithFields(logrus.Fields{
		"i2pstring_length": len(str),
	}).Debug("Successfully converted string to I2PString")
	return
}

// ReadI2PString returns I2PString from a []byte.
// The remaining bytes after the specified length are also returned.
// Returns a list of errors that occurred during parsing.
func ReadI2PString(data []byte) (str I2PString, remainder []byte, err error) {
	if len(data) == 0 {
		err = ErrZeroLength
		log.WithError(err).Error("Passed data with len == 0")
		return
	}
	log.WithFields(logrus.Fields{
		"input_length": len(data),
	}).Debug("Reading I2PString from bytes")
	length, _, err := NewInteger(data, 1)
	if err != nil {
		log.WithError(err).Error("Failed to read I2PString length")
		return
	}
	data_len := length.Int() + 1
	if data_len > len(data) {
		log.Errorf("I2PString length %d exceeds available data %d", data_len-1, len(data)-1)
		err = ErrDataTooShort
		log.WithError(err).Error("Failed to read I2PString")
		return
	}
	str = data[:data_len]
	remainder = data[data_len:]
	l, err := str.Length()
	if l != data_len-1 {
		err = ErrLengthMismatch
		log.WithFields(logrus.Fields{
			"expected_length": data_len - 1,
			"actual_length":   l,
		}).Error("I2PString length mismatch")
		return
	}
	log.WithFields(logrus.Fields{
		"string_length":    l,
		"remainder_length": len(remainder),
	}).Debug("Successfully read I2PString from bytes")
	return
}
