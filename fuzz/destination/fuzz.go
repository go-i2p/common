package exportable

import common "github.com/go-i2p/common/destination"

func Fuzz(data []byte) int {
	destination, _, err := common.ReadDestination(data)
	if err != nil {
		return 0
	}
	destination.Base32Address()
	destination.Base64()
	return 1
}
