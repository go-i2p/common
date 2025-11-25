// Package router_info implements the I2P RouterInfo common data structure
package router_info

import (
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

var log = logger.GetGoI2PLogger()

// Validate checks if the RouterInfo is properly initialized.
// Returns an error if the router info or its required components are invalid.
func (ri *RouterInfo) Validate() error {
	if ri == nil {
		return oops.Errorf("router info is nil")
	}
	if ri.router_identity == nil {
		return oops.Errorf("router identity is required")
	}
	if err := ri.router_identity.Validate(); err != nil {
		return oops.Errorf("invalid router identity: %w", err)
	}
	if ri.published == nil {
		return oops.Errorf("published date is required")
	}
	if ri.published.IsZero() {
		return oops.Errorf("published date cannot be zero")
	}
	if ri.size == nil {
		return oops.Errorf("size field is required")
	}
	if len(ri.addresses) == 0 {
		return oops.Errorf("router must have at least one address")
	}
	// Validate the size matches the actual number of addresses
	sizeValue := ri.size.Int()
	if sizeValue != len(ri.addresses) {
		return oops.Errorf("size mismatch: size field is %d but have %d addresses", sizeValue, len(ri.addresses))
	}
	if ri.options == nil {
		return oops.Errorf("options mapping is required")
	}
	if err := ri.options.Validate(); err != nil {
		return oops.Errorf("invalid options mapping: %w", err)
	}
	if ri.signature == nil {
		return oops.Errorf("signature is required")
	}
	return nil
}

// IsValid returns true if the RouterInfo is properly initialized.
// This is a convenience method that returns false instead of an error.
func (ri *RouterInfo) IsValid() bool {
	return ri.Validate() == nil
}
