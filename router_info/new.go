package router_info

import (
	"github.com/go-i2p/common/key_certificate"
	"github.com/samber/oops"
)

// OwnedRouterInfo creates a RouterInfo instance using the specified key certificate.
//
// Deprecated: This is an unimplemented stub that always returns an error.
// Use NewRouterInfo() for full RouterInfo construction with signing.
func OwnedRouterInfo(keyCertificate key_certificate.KeyCertificate) (*RouterInfo, error) {
	log.Error("OwnedRouterInfo is a deprecated unimplemented stub; use NewRouterInfo for full construction")
	return nil, oops.Errorf("OwnedRouterInfo is deprecated and unimplemented; use NewRouterInfo() instead")
}
