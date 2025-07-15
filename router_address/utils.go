// Package router_address implements the I2P RouterAddress common data structure
package router_address

import (
	"encoding/binary"
	"time"

	"github.com/samber/oops"
	"github.com/sirupsen/logrus"

	"github.com/go-i2p/common/data"
)

// ReadRouterAddress returns RouterAddress from a []byte.
// The remaining bytes after the specified length are also returned.
// Returns a list of errors that occurred during parsing.
func ReadRouterAddress(routerAddressData []byte) (router_address RouterAddress, remainder []byte, err error) {
	log.WithField("data_length", len(routerAddressData)).Debug("Reading RouterAddress from data")
	if len(routerAddressData) == 0 {
		log.WithField("at", "(RouterAddress) ReadRouterAddress").Error("error parsing RouterAddress: no data")
		err = oops.Errorf("error parsing RouterAddress: no data")
		return
	}
	router_address.TransportCost, remainder, err = data.NewInteger(routerAddressData, 1)
	if err != nil {
		log.WithFields(logrus.Fields{
			"at":     "(RouterAddress) ReadNewRouterAddress",
			"reason": "error parsing cost",
		}).Warn("error parsing RouterAddress")
	}
	router_address.ExpirationDate, remainder, err = data.NewDate(remainder)
	if err != nil {
		log.WithFields(logrus.Fields{
			"at":     "(RouterAddress) ReadNewRouterAddress",
			"reason": "error parsing expiration",
		}).Error("error parsing RouterAddress")
	}
	router_address.TransportType, remainder, err = data.ReadI2PString(remainder)
	if err != nil {
		log.WithFields(logrus.Fields{
			"at":     "(RouterAddress) ReadNewRouterAddress",
			"reason": "error parsing transport_style",
		}).Error("error parsing RouterAddress")
	}
	var errs []error
	router_address.TransportOptions, remainder, errs = data.NewMapping(remainder)
	for _, err := range errs {
		log.WithFields(logrus.Fields{
			"at":     "(RouterAddress) ReadNewRouterAddress",
			"reason": "error parsing options",
			"error":  err,
		}).Error("error parsing RozuterAddress")
	}
	return
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

	log.WithFields(logrus.Fields{
		"cost":          cost,
		"expiration":    expiration,
		"transportType": transportType,
		"options":       options,
	}).Debug("Successfully created new RouterAddress")

	return ra, nil
}
