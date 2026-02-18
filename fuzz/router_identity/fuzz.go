package exportable

import common "github.com/go-i2p/common/router_identity"

func Fuzz(data []byte) int {
	router_identity, _, err := common.ReadRouterIdentity(data)
	if err != nil || router_identity == nil {
		return 0
	}
	router_identity.Certificate()
	return 0
}
