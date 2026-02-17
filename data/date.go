// Package data implements common data structures used in higher level structures.
package data

import (
	"math"
	"time"

	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

/*
[I2P Date]
Accurate for version 0.9.67

Description
The number of milliseconds since midnight on Januyar 1, 1970 in the GMT timezone.
If the number is 0, the date is undefined or null.

Contents
8 byte Integer
*/

// Date is the represenation of an I2P Date.
//
// https://geti2p.net/spec/common-structures#date
type Date [8]byte

// Bytes returns the raw []byte content of a Date.
func (i Date) Bytes() []byte {
	return i[:]
}

// Int returns the Date as a Go integer.
func (i Date) Int() int {
	value, err := intFromBytes(i.Bytes())
	if err != nil {
		// Log error context for debugging
		// (logging already handled in intFromBytes)
		return 0
	}
	return value
}

// Time takes the value stored in date as an 8 byte big-endian integer representing the
// number of milliseconds since the beginning of unix time and converts it to a Go time.Time
// struct.
func (date Date) Time() (date_time time.Time) {
	millis := Integer(date[:])
	date_time = time.UnixMilli(int64(millis.Int()))
	return
}

// ReadDate creates a Date from []byte using the first DATE_SIZE bytes.
// Any data after DATE_SIZE is returned as a remainder.
func ReadDate(data []byte) (date Date, remainder []byte, err error) {
	if len(data) < 8 {
		log.WithFields(logger.Fields{
			"data": data,
		}).Error("ReadDate: data is too short")
		err = oops.Errorf("ReadDate: data is too short")
		return
	}
	copy(date[:], data[:8])
	remainder = data[8:]
	log.WithFields(logger.Fields{
		"date_value":       date.Int(),
		"remainder_length": len(remainder),
	}).Debug("Successfully read Date from data")
	return
}

// NewDate creates a new Date from []byte using ReadDate.
// Returns a pointer to Date unlike ReadDate.
func NewDate(data []byte) (date *Date, remainder []byte, err error) {
	objdate, remainder, err := ReadDate(data)
	if err != nil {
		log.WithError(err).Error("Failed to create new Date")
		return nil, remainder, err
	}

	date = &objdate
	log.WithFields(logger.Fields{
		"date_value":       date.Int(),
		"remainder_length": len(remainder),
	}).Debug("Successfully created new Date")
	return
}

// DateFromTime takes a time.Time and returns a data.Date
func DateFromTime(t time.Time) (date *Date, err error) {
	// Create a new Date
	date = new(Date)

	// Convert time to milliseconds since Unix epoch
	msec := t.UnixNano() / int64(1000000)

	// Convert to big-endian bytes
	for i := 7; i >= 0; i-- {
		date[i] = byte(msec & 0xff)
		msec >>= 8
	}

	log.WithFields(logger.Fields{
		"date_value": date.Int(),
		"time":       t,
	}).Debug("Successfully created Date from time.Time")

	return
}

// NewDateFromUnix creates a Date from a Unix timestamp (seconds) with validation.
// Returns error if timestamp is negative or exceeds maximum safe value.
func NewDateFromUnix(timestamp int64) (*Date, error) {
	if timestamp < 0 {
		return nil, oops.Errorf("timestamp cannot be negative: %d", timestamp)
	}
	// I2P dates are milliseconds since epoch, stored as 8-byte big-endian integer
	// Maximum safe value is when milliseconds fit in int64
	maxTimestamp := int64(math.MaxInt64 / 1000)
	if timestamp > maxTimestamp {
		return nil, oops.Errorf("timestamp too large: %d (max %d)", timestamp, maxTimestamp)
	}
	return DateFromTime(time.Unix(timestamp, 0))
}

// NewDateFromMillis creates a Date from milliseconds since epoch with validation.
// Returns error if milliseconds is negative.
func NewDateFromMillis(millis int64) (*Date, error) {
	if millis < 0 {
		return nil, oops.Errorf("milliseconds cannot be negative: %d", millis)
	}
	seconds := millis / 1000
	nanos := (millis % 1000) * 1000000
	return DateFromTime(time.Unix(seconds, nanos))
}

// IsZero returns true if the date represents zero time (undefined/null).
// According to I2P spec, a date value of 0 means undefined or null.
func (d Date) IsZero() bool {
	for _, b := range d {
		if b != 0 {
			return false
		}
	}
	return true
}
