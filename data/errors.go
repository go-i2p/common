package data

import (
	"fmt"
)

var (
	ErrZeroLength               = fmt.Errorf("error parsing string: zero length")
	ErrDataTooShort             = fmt.Errorf("string parsing warning: string data is shorter than specified by length")
	ErrDataTooLong              = fmt.Errorf("string parsing warning: string contains data beyond length")
	ErrLengthMismatch           = fmt.Errorf("error reading I2P string, length does not match data")
	ErrMappingLengthMismatch    = fmt.Errorf("warning parsing mapping: mapping length exceeds provided data")
	ErrMappingExpectedEquals    = fmt.Errorf("mapping format violation, expected =")
	ErrMappingExpectedSemicolon = fmt.Errorf("mapping format violation, expected ;")
)
