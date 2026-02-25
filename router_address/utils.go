// Package router_address implements the I2P RouterAddress common data structure
package router_address

import (
	"errors"

	"github.com/go-i2p/logger"
	"github.com/samber/oops"

	"github.com/go-i2p/common/data"
)

// ReadRouterAddress returns RouterAddress from a []byte.
// The remaining bytes after the specified length are also returned.
// Returns a list of errors that occurred during parsing.
// ErrNonZeroExpiration may be returned together with a valid RouterAddress to
// indicate a spec violation; callers should use errors.Is to test for it.
func ReadRouterAddress(routerAddressData []byte) (ra RouterAddress, remainder []byte, err error) {
	log.WithField("data_length", len(routerAddressData)).Debug("Reading RouterAddress from data")

	if err = validateRouterAddressData(routerAddressData); err != nil {
		return
	}

	remainder, err = parseTransportCost(&ra, routerAddressData)
	if err != nil {
		return
	}

	// parseExpirationDate may return ErrNonZeroExpiration as a non-fatal warning.
	var expirationWarning error
	remainder, err = parseExpirationDate(&ra, remainder)
	if err != nil {
		if !errors.Is(err, ErrNonZeroExpiration) {
			return // fatal parse error
		}
		expirationWarning = err
		err = nil
	}

	remainder, err = parseTransportType(&ra, remainder)
	if err != nil {
		return
	}

	remainder, err = parseTransportOptions(&ra, remainder)
	if err == nil {
		err = expirationWarning
	}
	return
}

// validateRouterAddressData validates that data meets the minimum size requirement.
// Returns error if no data is provided or data is too small.
func validateRouterAddressData(data []byte) error {
	if len(data) == 0 {
		log.WithField("at", "(RouterAddress) validateRouterAddressData").Error("error parsing RouterAddress: no data")
		return oops.Errorf("%w", ErrNoData)
	}
	if len(data) < ROUTER_ADDRESS_MIN_SIZE {
		log.WithFields(logger.Fields{
			"at":       "(RouterAddress) validateRouterAddressData",
			"expected": ROUTER_ADDRESS_MIN_SIZE,
			"got":      len(data),
		}).Error("error parsing RouterAddress: data too small")
		return oops.Errorf("%w: expected at least %d bytes, got %d", ErrDataTooSmall, ROUTER_ADDRESS_MIN_SIZE, len(data))
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
// Returns ErrNonZeroExpiration (wrapped) as a non-fatal warning when non-zero;
// callers should still parse the address but may signal the spec violation.
func parseExpirationDate(ra *RouterAddress, routerData []byte) ([]byte, error) {
	expirationDate, remainder, err := data.NewDate(routerData)
	if err != nil {
		log.WithFields(logger.Fields{
			"at":     "(RouterAddress) parseExpirationDate",
			"reason": "error parsing expiration",
		}).Error("error parsing RouterAddress")
		return remainder, err
	}
	ra.ExpirationDate = expirationDate
	if !isAllZeros(expirationDate[:]) {
		log.Warn("RouterAddress expiration is non-zero; spec requires all zeros (I2P 0.9.12+)")
		return remainder, oops.Errorf("%w", ErrNonZeroExpiration)
	}
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
// Rejects zero-length transport style strings as invalid per spec.
func parseTransportType(ra *RouterAddress, routerData []byte) ([]byte, error) {
	transportType, remainder, err := data.ReadI2PString(routerData)
	if err != nil {
		log.WithFields(logger.Fields{
			"at":     "(RouterAddress) parseTransportType",
			"reason": "error parsing transport_style",
		}).Error("error parsing RouterAddress")
		return remainder, err
	}
	content, contentErr := transportType.Data()
	if contentErr == nil && len(content) == 0 {
		log.WithField("at", "(RouterAddress) parseTransportType").Error("transport_style is empty")
		return remainder, oops.Errorf("%w", ErrEmptyTransportStyle)
	}
	ra.TransportType = transportType
	return remainder, nil
}

// parseTransportOptions parses the transport options mapping from data.
// Returns remaining data after parsing and any error encountered.
// Errors from the mapping parser are logged as warnings when options is non-nil
// (trailing-data warnings are normal in RouterAddress context); the mapping error
// is only propagated as a hard failure when the mapping itself could not be parsed
// (nil result).
func parseTransportOptions(ra *RouterAddress, routerData []byte) ([]byte, error) {
	transportOptions, remainder, errs := data.NewMapping(routerData)
	ra.TransportOptions = transportOptions
	if len(errs) > 0 {
		for _, mappingErr := range errs {
			log.WithFields(logger.Fields{
				"at":     "(RouterAddress) parseTransportOptions",
				"reason": "error parsing options",
				"error":  mappingErr,
			}).Warn("non-fatal warning parsing RouterAddress options")
		}
		if transportOptions == nil {
			return remainder, oops.Errorf("error parsing RouterAddress options: %v", errs[0])
		}
	}
	return remainder, nil
}
