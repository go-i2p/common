package router_info

import "github.com/go-i2p/common/key_certificate"

// OwnedRouterInfo creates a RouterInfo instance using the specified key certificate.
//
// Deprecated: This is an unimplemented stub that always returns nil.
// Callers MUST check the return value for nil to avoid nil pointer panics.
// Use NewRouterInfo() for full RouterInfo construction with signing.
func OwnedRouterInfo(keyCertificate key_certificate.KeyCertificate) *RouterInfo {
	log.Error("OwnedRouterInfo is a deprecated unimplemented stub; use NewRouterInfo for full construction")
	return nil
}
