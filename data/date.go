// Package data implements common data structures used in higher level structures.
package data

import (
	"time"

	"github.com/samber/oops"
	"github.com/sirupsen/logrus"
)

/*
[I2P Date]
Accurate for version 0.9.49

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
	seconds := Integer(date[:])
	date_time = time.Unix(0, int64(seconds.Int()*1000000))
	return
}

// ReadDate creates a Date from []byte using the first DATE_SIZE bytes.
// Any data after DATE_SIZE is returned as a remainder.
func ReadDate(data []byte) (date Date, remainder []byte, err error) {
	if len(data) < 8 {
		log.WithFields(logrus.Fields{
			"data": data,
		}).Error("ReadDate: data is too short")
		err = oops.Errorf("ReadDate: data is too short")
		return
	}
	copy(date[:], data[:8])
	remainder = data[8:]
	log.WithFields(logrus.Fields{
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
	log.WithFields(logrus.Fields{
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

	log.WithFields(logrus.Fields{
		"date_value": date.Int(),
		"time":       t,
	}).Debug("Successfully created Date from time.Time")

	return
}
