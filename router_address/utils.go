// Package router_address implements the I2P RouterAddress common data structure
package router_address

import (
	"encoding/binary"
	"time"

	"github.com/go-i2p/logger"
	"github.com/samber/oops"

	"github.com/go-i2p/common/data"
)

// ReadRouterAddress returns RouterAddress from a []byte.
// The remaining bytes after the specified length are also returned.
// Returns a list of errors that occurred during parsing.
func ReadRouterAddress(routerAddressData []byte) (router_address RouterAddress, remainder []byte, err error) {
	log.WithField("data_length", len(routerAddressData)).Debug("Reading RouterAddress from data")

	if err = validateRouterAddressData(routerAddressData); err != nil {
		return
	}

	remainder, err = parseTransportCost(&router_address, routerAddressData)
	if err != nil {
		return
	}

	remainder, err = parseExpirationDate(&router_address, remainder)
	if err != nil {
		return
	}

	remainder, err = parseTransportType(&router_address, remainder)
	if err != nil {
		return
	}

	remainder, err = parseTransportOptions(&router_address, remainder)
	return
}

// validateRouterAddressData validates that data is not empty.
// Returns error if no data is provided.
func validateRouterAddressData(data []byte) error {
	if len(data) == 0 {
		log.WithField("at", "(RouterAddress) validateRouterAddressData").Error("error parsing RouterAddress: no data")
		return oops.Errorf("error parsing RouterAddress: no data")
	}
	return nil
}

// parseTransportCost parses the transport cost field from data.
// Returns remaining data after parsing and any error encountered.
func parseTransportCost(router_address *RouterAddress, routerData []byte) ([]byte, error) {
	cost, remainder, err := data.NewInteger(routerData, 1)
	if err != nil {
		log.WithFields(logger.Fields{
			"at":     "(RouterAddress) parseTransportCost",
			"reason": "error parsing cost",
		}).Warn("error parsing RouterAddress")
		return remainder, err
	}
	router_address.TransportCost = cost
	return remainder, nil
}

// parseExpirationDate parses the expiration date field from data.
// Returns remaining data after parsing and any error encountered.
func parseExpirationDate(router_address *RouterAddress, routerData []byte) ([]byte, error) {
	expirationDate, remainder, err := data.NewDate(routerData)
	if err != nil {
		log.WithFields(logger.Fields{
			"at":     "(RouterAddress) parseExpirationDate",
			"reason": "error parsing expiration",
		}).Error("error parsing RouterAddress")
		return remainder, err
	}
	router_address.ExpirationDate = expirationDate
	return remainder, nil
}

// parseTransportType parses the transport type field from data.
// Returns remaining data after parsing and any error encountered.
func parseTransportType(router_address *RouterAddress, routerData []byte) ([]byte, error) {
	transportType, remainder, err := data.ReadI2PString(routerData)
	if err != nil {
		log.WithFields(logger.Fields{
			"at":     "(RouterAddress) parseTransportType",
			"reason": "error parsing transport_style",
		}).Error("error parsing RouterAddress")
		return remainder, err
	}
	router_address.TransportType = transportType
	return remainder, nil
}

// parseTransportOptions parses the transport options mapping from data.
// Returns remaining data after parsing and any error encountered.
func parseTransportOptions(router_address *RouterAddress, routerData []byte) ([]byte, error) {
	transportOptions, remainder, errs := data.NewMapping(routerData)
	for _, err := range errs {
		log.WithFields(logger.Fields{
			"at":     "(RouterAddress) parseTransportOptions",
			"reason": "error parsing options",
			"error":  err,
		}).Error("error parsing RouterAddress")
	}
	router_address.TransportOptions = transportOptions
	return remainder, nil
}

// NewRouterAddress creates a new RouterAddress with the provided parameters.
// Returns a pointer to RouterAddress.
func NewRouterAddress(cost uint8, expiration time.Time, transportType string, options map[string]string) (*RouterAddress, error) {
	log.Debug("Creating new RouterAddress")

	// Create TransportCost as an Integer (1 byte)
	transportCost, err := data.NewIntegerFromInt(int(cost), 1)
	if err != nil {
		log.WithError(err).Error("Failed to create TransportCost Integer")
		return nil, err
	}

	// Create ExpirationDate as a Date
	millis := expiration.UnixNano() / int64(time.Millisecond)
	dateBytes := make([]byte, data.DATE_SIZE)
	binary.BigEndian.PutUint64(dateBytes, uint64(millis))
	expirationDate, _, err := data.NewDate(dateBytes)
	if err != nil {
		log.WithError(err).Error("Failed to create ExpirationDate")
		return nil, err
	}

	// Create TransportType as an I2PString
	transportTypeStr, err := data.ToI2PString(transportType)
	if err != nil {
		log.WithError(err).Error("Failed to create TransportType I2PString")
		return nil, err
	}

	// Create TransportOptions as a Mapping
	transportOptions, err := data.GoMapToMapping(options)
	if err != nil {
		log.WithError(err).Error("Failed to create TransportOptions Mapping")
		return nil, err
	}

	// Create RouterAddress
	ra := &RouterAddress{
		TransportCost:    transportCost,
		ExpirationDate:   expirationDate,
		TransportType:    transportTypeStr,
		TransportOptions: transportOptions,
	}

	log.WithFields(logger.Fields{
		"cost":          cost,
		"expiration":    expiration,
		"transportType": transportType,
		"options":       options,
	}).Debug("Successfully created new RouterAddress")

	return ra, nil
}
