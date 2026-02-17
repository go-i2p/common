// Package router_address implements the I2P RouterAddress common data structure
package router_address

import (
	"net"
	"time"

	"github.com/go-i2p/common/data"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

var log = logger.GetGoI2PLogger()

// ex_addr is a package-level variable used to verify RouterAddress implements net.Addr
var ex_addr net.Addr = &RouterAddress{}

// NewRouterAddress creates a new RouterAddress with the provided parameters.
// Validates that the transport type is not empty and that required options are provided.
// Returns a pointer to RouterAddress.
func NewRouterAddress(cost uint8, expiration time.Time, transportType string, options map[string]string) (*RouterAddress, error) {
	log.Debug("Creating new RouterAddress")

	// Validate transport type is not empty
	if transportType == "" {
		return nil, oops.Errorf("transport type cannot be empty")
	}

	transportCost, err := createTransportCost(cost)
	if err != nil {
		return nil, err
	}

	expirationDate, err := createExpirationDate(expiration)
	if err != nil {
		return nil, err
	}

	transportTypeStr, err := createTransportType(transportType)
	if err != nil {
		return nil, err
	}

	transportOptions, err := createTransportOptions(options)
	if err != nil {
		return nil, err
	}

	ra := buildRouterAddress(transportCost, expirationDate, transportTypeStr, transportOptions)

	log.WithFields(logger.Fields{
		"cost":          cost,
		"expiration":    expiration,
		"transportType": transportType,
		"options":       options,
	}).Debug("Successfully created new RouterAddress")

	return ra, nil
}

// Validate checks if the RouterAddress is properly initialized.
func (ra *RouterAddress) Validate() error {
	if ra == nil {
		return oops.Errorf("router address is nil")
	}
	if ra.TransportCost == nil {
		return oops.Errorf("transport cost is required")
	}
	if ra.ExpirationDate == nil {
		return oops.Errorf("expiration date is required")
	}
	if ra.TransportType == nil || len(ra.TransportType) == 0 {
		return oops.Errorf("transport type is required")
	}
	if ra.TransportOptions == nil {
		return oops.Errorf("transport options are required")
	}
	if err := ra.TransportOptions.Validate(); err != nil {
		return oops.Errorf("invalid transport options: %w", err)
	}
	return nil
}

// IsValid returns true if the RouterAddress is properly initialized.
func (ra *RouterAddress) IsValid() bool {
	return ra.Validate() == nil
}

// createTransportCost creates the TransportCost field as an Integer (1 byte).
// Returns error if the cost value cannot be converted to an Integer.
func createTransportCost(cost uint8) (*data.Integer, error) {
	transportCost, err := data.NewIntegerFromInt(int(cost), 1)
	if err != nil {
		log.WithError(err).Error("Failed to create TransportCost Integer")
		return nil, err
	}
	return transportCost, nil
}

// createExpirationDate creates the ExpirationDate field as a Date.
// Per I2P spec, the expiration MUST always be all zeros.
// The expiration parameter is accepted for API compatibility but ignored.
func createExpirationDate(expiration time.Time) (*data.Date, error) {
	dateBytes := make([]byte, data.DATE_SIZE) // all zeros per spec
	expirationDate, _, err := data.NewDate(dateBytes)
	if err != nil {
		log.WithError(err).Error("Failed to create ExpirationDate")
		return nil, err
	}
	return expirationDate, nil
}

// createTransportType creates the TransportType field as an I2PString.
// Returns error if the transport type string exceeds maximum size.
func createTransportType(transportType string) (data.I2PString, error) {
	transportTypeStr, err := data.ToI2PString(transportType)
	if err != nil {
		log.WithError(err).Error("Failed to create TransportType I2PString")
		return data.I2PString{}, err
	}
	return transportTypeStr, nil
}

// createTransportOptions creates the TransportOptions field as a Mapping.
// Returns error if the options map cannot be converted to a Mapping.
func createTransportOptions(options map[string]string) (*data.Mapping, error) {
	transportOptions, err := data.GoMapToMapping(options)
	if err != nil {
		log.WithError(err).Error("Failed to create TransportOptions Mapping")
		return nil, err
	}
	return transportOptions, nil
}

// buildRouterAddress constructs a RouterAddress from the provided components.
// Returns a pointer to the initialized RouterAddress.
func buildRouterAddress(transportCost *data.Integer, expirationDate *data.Date, transportType data.I2PString, transportOptions *data.Mapping) *RouterAddress {
	return &RouterAddress{
		TransportCost:    transportCost,
		ExpirationDate:   expirationDate,
		TransportType:    transportType,
		TransportOptions: transportOptions,
	}
}
