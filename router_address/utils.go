// Package router_address implements the I2P RouterAddress common data structure
package router_address

import (
	"errors"
	"strings"

	"github.com/go-i2p/logger"
	"github.com/samber/oops"

	"github.com/go-i2p/common/data"
)

// ReadRouterAddress returns RouterAddress from a []byte.
// The remaining bytes after the specified length are also returned.
// Returns an error if parsing failed.
// ErrNonZeroExpiration may be returned together with a valid RouterAddress to
// indicate a spec violation; callers should use errors.Is to test for it.
func ReadRouterAddress(routerAddressData []byte) (ra RouterAddress, remainder []byte, err error) {
	log.WithFields(logger.Fields{"pkg": "router_address", "func": "ReadRouterAddress", "data_length": len(routerAddressData)}).Debug("Reading RouterAddress from data")

	if err = validateRouterAddressData(routerAddressData); err != nil {
		return ra, remainder, err
	}

	remainder, err = parseTransportCost(&ra, routerAddressData)
	if err != nil {
		return ra, remainder, err
	}

	var expirationWarning error
	remainder, expirationWarning, err = handleExpirationWarning(&ra, remainder)
	if err != nil {
		return ra, remainder, err
	}

	remainder, err = parseTransportType(&ra, remainder)
	if err != nil {
		return ra, remainder, err
	}

	remainder, err = parseTransportOptions(&ra, remainder)
	if err == nil {
		err = expirationWarning
	}
	return ra, remainder, err
}

// handleExpirationWarning processes the expiration date parsing result, separating
// fatal errors from the non-fatal ErrNonZeroExpiration warning per I2P spec.
func handleExpirationWarning(ra *RouterAddress, data []byte) (remainder []byte, warning, err error) {
	remainder, err = parseExpirationDate(ra, data)
	if err != nil {
		if !errors.Is(err, ErrNonZeroExpiration) {
			return remainder, warning, err // fatal parse error
		}
		warning = err
		err = nil
	}
	return remainder, warning, err
}

// validateRouterAddressData validates that data meets the minimum size requirement.
// Returns error if no data is provided or data is too small.
func validateRouterAddressData(data []byte) error {
	if len(data) == 0 {
		log.WithFields(logger.Fields{"pkg": "router_address", "func": "validateRouterAddressData"}).Error("error parsing RouterAddress: no data")
		return oops.Errorf("%w", ErrNoData)
	}
	if len(data) < ROUTER_ADDRESS_MIN_SIZE {
		log.WithFields(logger.Fields{
			"pkg":      "router_address",
			"func":     "validateRouterAddressData",
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
			"pkg":    "router_address",
			"func":   "parseTransportCost",
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
			"pkg":    "router_address",
			"func":   "parseExpirationDate",
			"reason": "error parsing expiration",
		}).Error("error parsing RouterAddress")
		return remainder, err
	}
	ra.ExpirationDate = expirationDate
	if !isAllZeros(expirationDate[:]) {
		log.WithFields(logger.Fields{"pkg": "router_address", "func": "parseExpirationDate"}).Warn("RouterAddress expiration is non-zero; spec requires all zeros (I2P 0.9.12+)")
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
//
// Rejects zero-length transport style strings: this structure's spec types the
// field as "String, 1-256 bytes", which requires at least one content byte, and
// that structure-specific statement is taken as controlling over the generic
// String section's "Length may be 0". The consequence is that a wire record
// carrying an empty transport style is rejected rather than round-tripped.
func parseTransportType(ra *RouterAddress, routerData []byte) ([]byte, error) {
	transportType, remainder, err := data.ReadI2PString(routerData)
	if err != nil {
		log.WithFields(logger.Fields{
			"pkg":    "router_address",
			"func":   "parseTransportType",
			"reason": "error parsing transport_style",
		}).Error("error parsing RouterAddress")
		return remainder, err
	}
	content, contentErr := transportType.Data()
	if contentErr == nil && len(content) == 0 {
		log.WithFields(logger.Fields{"pkg": "router_address", "func": "parseTransportType"}).Error("transport_style is empty")
		return remainder, oops.Errorf("%w", ErrEmptyTransportStyle)
	}
	ra.TransportType = transportType
	return remainder, nil
}

// parseTransportOptions parses the transport options mapping from data.
// Returns remaining data after parsing and any error encountered.
//
// The trailing-data warning ("data exists beyond length of mapping") is
// expected when a mapping is embedded in a larger structure and is filtered
// out. All other mapping errors are structural format violations prohibited
// by the specification — duplicate keys, missing '=' or ';' delimiters, a
// declared size that exceeds the available data, unconsumed bytes — and are
// propagated as hard parse errors so that malformed RouterAddress data is
// never accepted as valid. This mirrors the categorization the router_info
// package applies to its own options mapping.
func parseTransportOptions(ra *RouterAddress, routerData []byte) ([]byte, error) {
	transportOptions, remainder, errs := data.NewMapping(routerData)
	ra.TransportOptions = transportOptions
	if len(errs) > 0 {
		var critical []error
		for _, mappingErr := range errs {
			if isTrailingDataWarning(mappingErr) {
				log.WithFields(logger.Fields{
					"pkg":    "router_address",
					"func":   "parseTransportOptions",
					"reason": "trailing data beyond mapping length (expected in embedded context)",
					"error":  mappingErr,
				}).Debug("non-fatal warning parsing RouterAddress options")
				continue
			}
			critical = append(critical, mappingErr)
		}
		if len(critical) > 0 {
			log.WithFields(logger.Fields{
				"pkg":    "router_address",
				"func":   "parseTransportOptions",
				"reason": "mapping format violation",
				"error":  critical[0],
			}).Error("rejecting RouterAddress with malformed transport options")
			return remainder, oops.Errorf("error parsing RouterAddress options: %v", critical[0])
		}
	}
	return remainder, nil
}

// isTrailingDataWarning reports whether err is the benign "data exists beyond
// length of mapping" warning rather than a structural mapping violation.
func isTrailingDataWarning(err error) bool {
	return err != nil && strings.Contains(err.Error(), "data exists beyond length of mapping")
}
