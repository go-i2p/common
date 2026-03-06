package exportable

import common "github.com/go-i2p/common/router_identity"

func Fuzz(data []byte) int {
	ri, _, err := common.ReadRouterIdentity(data)
	if err != nil || ri == nil {
		return 0
	}
	// Exercise key accessors for crash/panic resistance
	ri.Certificate()
	_, _ = ri.Hash()
	_, _ = ri.Bytes()
	_ = ri.String()
	_ = ri.AsDestination()
	return 0
}
