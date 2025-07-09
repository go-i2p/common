package router_info

import "github.com/go-i2p/common/key_certificate"

// OwnedRouterInfo creates a RouterInfo instance using the specified key certificate.
// Moved from: new.go
func OwnedRouterInfo(keyCertificate key_certificate.KeyCertificate) *RouterInfo {
	return &RouterInfo{
		// ...
	}
}
