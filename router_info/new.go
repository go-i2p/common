package router_info

import "github.com/go-i2p/common/key_certificate"

// OwnedRouterInfo creates a RouterInfo instance using the specified key certificate.
//
// Deprecated: This is an unimplemented stub that returns nil.
// Use NewRouterInfo() for full RouterInfo construction with signing.
func OwnedRouterInfo(keyCertificate key_certificate.KeyCertificate) *RouterInfo {
	log.Warn("OwnedRouterInfo is a deprecated stub; use NewRouterInfo for full construction")
	return nil
}
