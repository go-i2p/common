// Package router_address implements the I2P RouterAddress common data structure
package router_address

import (
	"github.com/go-i2p/logger"
	"github.com/samber/oops"

	"github.com/go-i2p/common/data"
)

// ReadRouterAddress returns RouterAddress from a []byte.
// The remaining bytes after the specified length are also returned.
// Returns a list of errors that occurred during parsing.
func ReadRouterAddress(routerAddressData []byte) (ra RouterAddress, remainder []byte, err error) {
	log.WithField("data_length", len(routerAddressData)).Debug("Reading RouterAddress from data")

	if err = validateRouterAddressData(routerAddressData); err != nil {
		return
	}

	remainder, err = parseTransportCost(&ra, routerAddressData)
	if err != nil {
		return
	}

	remainder, err = parseExpirationDate(&ra, remainder)
	if err != nil {
		return
	}

	remainder, err = parseTransportType(&ra, remainder)
	if err != nil {
		return
	}

	remainder, err = parseTransportOptions(&ra, remainder)
	return
}

// validateRouterAddressData validates that data meets the minimum size requirement.
// Returns error if no data is provided or data is too small.
func validateRouterAddressData(data []byte) error {
	if len(data) == 0 {
		log.WithField("at", "(RouterAddress) validateRouterAddressData").Error("error parsing RouterAddress: no data")
		return oops.Errorf("error parsing RouterAddress: no data")
	}
	if len(data) < ROUTER_ADDRESS_MIN_SIZE {
		log.WithFields(logger.Fields{
			"at":       "(RouterAddress) validateRouterAddressData",
			"expected": ROUTER_ADDRESS_MIN_SIZE,
			"got":      len(data),
		}).Error("error parsing RouterAddress: data too small")
		return oops.Errorf("error parsing RouterAddress: not enough data (expected at least %d bytes, got %d bytes)", ROUTER_ADDRESS_MIN_SIZE, len(data))
	}
	return nil
}

// parseTransportCost parses the transport cost field from data.
// Returns remaining data after parsing and any error encountered.
func parseTransportCost(ra *RouterAddress, routerData []byte) ([]byte, error) {
	cost, remainder, err := data.NewInteger(routerData, 1)
	if err != nil {
		log.WithFields(logger.Fields{
			"at":     "(RouterAddress) parseTransportCost",
			"reason": "error parsing cost",
		}).Warn("error parsing RouterAddress")
		return remainder, err
	}
	ra.TransportCost = cost
	return remainder, nil
}

// parseExpirationDate parses the expiration date field from data.
// Per I2P spec, the expiration field MUST be all zeros.
// Returns remaining data after parsing and any error encountered.
func parseExpirationDate(ra *RouterAddress, routerData []byte) ([]byte, error) {
	expirationDate, remainder, err := data.NewDate(routerData)
	if err != nil {
		log.WithFields(logger.Fields{
			"at":     "(RouterAddress) parseExpirationDate",
			"reason": "error parsing expiration",
		}).Error("error parsing RouterAddress")
		return remainder, err
	}
	if !isAllZeros(expirationDate[:]) {
		log.Warn("RouterAddress expiration is non-zero; spec requires all zeros")
	}
	ra.ExpirationDate = expirationDate
	return remainder, nil
}

// isAllZeros checks if all bytes in the slice are zero.
func isAllZeros(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

// parseTransportType parses the transport type field from data.
// Returns remaining data after parsing and any error encountered.
func parseTransportType(ra *RouterAddress, routerData []byte) ([]byte, error) {
	transportType, remainder, err := data.ReadI2PString(routerData)
	if err != nil {
		log.WithFields(logger.Fields{
			"at":     "(RouterAddress) parseTransportType",
			"reason": "error parsing transport_style",
		}).Error("error parsing RouterAddress")
		return remainder, err
	}
	ra.TransportType = transportType
	return remainder, nil
}

// parseTransportOptions parses the transport options mapping from data.
// Returns remaining data after parsing and any error encountered.
// Propagates errors only when the mapping cannot be parsed (nil result).
// Warnings about trailing data are expected in RouterAddress context and logged only.
func parseTransportOptions(ra *RouterAddress, routerData []byte) ([]byte, error) {
	transportOptions, remainder, errs := data.NewMapping(routerData)
	for _, err := range errs {
		log.WithFields(logger.Fields{
			"at":     "(RouterAddress) parseTransportOptions",
			"reason": "error parsing options",
			"error":  err,
		}).Error("error parsing RouterAddress")
	}
	ra.TransportOptions = transportOptions
	if transportOptions == nil && len(errs) > 0 {
		return remainder, oops.Errorf("error parsing RouterAddress options: %v", errs[0])
	}
	return remainder, nil
}
