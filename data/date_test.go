package data

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTimeFromMilliseconds(t *testing.T) {
	assert := assert.New(t)

	next_day := Date{0x00, 0x00, 0x00, 0x00, 0x05, 0x26, 0x5c, 0x00}
	go_time := next_day.Time()

	assert.Equal(int64(86400), go_time.Unix(), "Date.Time() did not parse time in milliseconds")
}
