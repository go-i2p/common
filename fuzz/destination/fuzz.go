package exportable

import common "github.com/go-i2p/common/destination"

func Fuzz(data []byte) int {
	destination, _, _ := common.ReadDestination(data)
	destination.Base32Address()
	destination.Base64()
	return 0
}
