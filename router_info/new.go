package router_info

import "github.com/go-i2p/common/key_certificate"

// OwnedRouterInfo creates a RouterInfo instance using the specified key certificate.
func OwnedRouterInfo(keyCertificate key_certificate.KeyCertificate) *RouterInfo {
	return &RouterInfo{
		// ...
	}
}
