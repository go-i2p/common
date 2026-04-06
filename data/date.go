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
The number of milliseconds since midnight on January 1, 1970 in the GMT timezone.
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
// WARNING: For Date values >= 2^63 ms since epoch, this method returns 0
// because the unsigned I2P Date value exceeds Go's signed int range.
// Use Date.Time() for reliable, full-range date handling.
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
// struct. Uses unsigned decoding to correctly handle the full range of I2P Date values.
//
// If the unsigned millisecond value exceeds math.MaxInt64 (high bit set), Time returns
// the zero time.Time{}, since Go's time.UnixMilli cannot represent such large values.
// Callers should check for zero time if working with dates that may have the high bit set.
func (date Date) Time() (date_time time.Time) {
	millis := Integer(date[:])
	uval, err := millis.UintSafe()
	if err != nil {
		return time.Time{}
	}
	if uval > uint64(math.MaxInt64) {
		log.WithFields(logger.Fields{"pkg": "data", "func": "Date.Time"}).Warn("Date.Time(): unsigned millisecond value exceeds math.MaxInt64, returning zero time")
		return time.Time{}
	}
	date_time = time.UnixMilli(int64(uval))
	return date_time
}

// ReadDate creates a Date from []byte using the first DATE_SIZE bytes.
// Any data after DATE_SIZE is returned as a remainder.
func ReadDate(data []byte) (date Date, remainder []byte, err error) {
	if len(data) < 8 {
		log.WithFields(logger.Fields{
			"pkg": "data", "func": "ReadDate",
			"data": data,
		}).Error("ReadDate: data is too short")
		err = oops.Errorf("ReadDate: data is too short")
		return date, remainder, err
	}
	copy(date[:], data[:8])
	remainder = data[8:]
	log.WithFields(logger.Fields{
		"pkg": "data", "func": "ReadDate",
		"date_value":       date.Int(),
		"remainder_length": len(remainder),
	}).Debug("Successfully read Date from data")
	return date, remainder, err
}

// NewDate creates a new Date from []byte using ReadDate.
// Returns a pointer to Date unlike ReadDate.
func NewDate(data []byte) (date *Date, remainder []byte, err error) {
	objdate, remainder, err := ReadDate(data)
	if err != nil {
		log.WithFields(logger.Fields{"pkg": "data", "func": "NewDate"}).WithError(err).Error("Failed to create new Date")
		return nil, remainder, err
	}

	date = &objdate
	log.WithFields(logger.Fields{
		"pkg": "data", "func": "NewDate",
		"date_value":       date.Int(),
		"remainder_length": len(remainder),
	}).Debug("Successfully created new Date")
	return date, remainder, err
}

// DateFromTime takes a time.Time and returns a data.Date.
// Returns error if the time is before the Unix epoch (January 1, 1970).
func DateFromTime(t time.Time) (date *Date, err error) {
	// Reject pre-epoch times for consistency with NewDateFromUnix and NewDateFromMillis
	if t.Before(time.Unix(0, 0)) {
		return nil, oops.Errorf("DateFromTime: time is before Unix epoch: %v", t)
	}

	date = new(Date)

	// Use UnixMilli() instead of UnixNano()/1000000 to avoid int64 overflow
	// for dates beyond ~2262-04-11 (Go 1.17+)
	msec := t.UnixMilli()

	// Convert to big-endian bytes
	for i := 7; i >= 0; i-- {
		date[i] = byte(msec & 0xff)
		msec >>= 8
	}

	log.WithFields(logger.Fields{
		"pkg": "data", "func": "DateFromTime",
		"time": t,
	}).Debug("Successfully created Date from time.Time")

	return date, err
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

// Validate checks that the Date is structurally valid.
// A Date is always 8 bytes (fixed-size array), so the only validation is
// whether it represents a non-zero (defined) time.
// Returns nil if the Date is valid (non-zero).
func (d Date) Validate() error {
	if d.IsZero() {
		return oops.Errorf("Date is zero (undefined/null)")
	}
	return nil
}

// IsValid returns true if the Date represents a defined (non-zero) time.
func (d Date) IsValid() bool {
	return !d.IsZero()
}
