package data

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

var log = logger.GetGoI2PLogger()

// intFromBytes interprets a slice of bytes from length 0 to length 8 as a big-endian
// integer and returns an int representation.
// Used in: integer.go
// intFromBytes interprets a slice of bytes from length 0 to length 8 as a big-endian
// integer and returns an int representation. Returns error for empty input.
func intFromBytes(number []byte) (value int, err error) {
	numLen := len(number)
	if numLen == 0 {
		log.WithFields(logger.Fields{"at": "intFromBytes", "reason": "empty input slice"}).Error("cannot convert empty byte slice to integer")
		err = oops.Errorf("intFromBytes: empty input slice")
		return 0, err
	}
	if numLen < MAX_INTEGER_SIZE {
		paddedNumber := make([]byte, MAX_INTEGER_SIZE)
		copy(paddedNumber[MAX_INTEGER_SIZE-numLen:], number)
		number = paddedNumber
	}
	value = int(binary.BigEndian.Uint64(number))
	return value, nil
}

// WrapErrors compiles a slice of errors and returns them wrapped together as a single error.
// Used in: errors.go
func WrapErrors(errs []error) error {
	var err error
	for i, e := range errs {
		err = oops.Errorf("%v\n\t%d: %v", err, i, e)
	}
	return err
}

// PrintErrors prints a formatted list of errors to the console.
// Used in: errors.go
func PrintErrors(errs []error) {
	for i, e := range errs {
		fmt.Printf("\t%d: %v\n", i, e)
	}
}

// stopValueRead checks if the string parsing error indicates that the Mapping
// should no longer be parsed.
// Used in: mapping.go
func stopValueRead(err error) bool {
	result := errors.Is(err, ErrZeroLength)
	if result {
		log.WithError(err).Debug("Stopping value read due to zero length error")
	}
	return result
}

// beginsWith determines if the first byte in a slice of bytes is the provided byte.
// Used in: mapping.go
func beginsWith(bytes []byte, chr byte) bool {
	result := len(bytes) != 0 && bytes[0] == chr
	log.WithFields(logger.Fields{
		"bytes_length":  len(bytes),
		"expected_char": string(chr),
		"result":        result,
	}).Debug("Checked if bytes begin with specific character")
	return result
}
