package router_info

import "github.com/go-i2p/common/key_certificate"

// OwnedRouterInfo creates a RouterInfo instance using the specified key certificate.
//
// NOTE: This is a stub. Use NewRouterInfo() for full construction with signing.
// OwnedRouterInfo is intended for future use when self-owned router info
// construction from a key certificate alone is needed.
//
// Deprecated: Use NewRouterInfo instead.
func OwnedRouterInfo(keyCertificate key_certificate.KeyCertificate) *RouterInfo {
	log.Warn("OwnedRouterInfo is a stub; use NewRouterInfo for full construction")
	return &RouterInfo{}
}
