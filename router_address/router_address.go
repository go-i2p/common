// Package router_address implements the I2P RouterAddress common data structure
package router_address

import (
	"encoding"
	"net"
	"time"

	"github.com/go-i2p/common/data"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// Compile-time assertion that RouterAddress implements net.Addr.
var _ net.Addr = (*RouterAddress)(nil)

// Compile-time assertions that RouterAddress implements encoding.BinaryMarshaler
// and encoding.BinaryUnmarshaler.
var (
	_ encoding.BinaryMarshaler   = (*RouterAddress)(nil)
	_ encoding.BinaryUnmarshaler = (*RouterAddress)(nil)
)

// NewRouterAddress creates a new RouterAddress with the provided parameters.
// Validates that the transport type is not empty and that required options are provided.
//
// The expiration parameter is accepted for API compatibility but is always ignored;
// the spec says "Expiration is currently unused, always null (all zeroes) ... Routers
// MUST set this field to all zeros", and although release 0.9.12 again recognizes a
// non-zero expiration, the spec states it must not be used until most of the network
// recognizes it. Callers should therefore pass time.Time{} (zero value); a non-zero
// value produces a log warning and is otherwise silently discarded.
//
// Returns a pointer to RouterAddress.
func NewRouterAddress(cost uint8, expiration time.Time, transportType string, options map[string]string) (*RouterAddress, error) {
	log.WithFields(logger.Fields{"pkg": "router_address", "func": "NewRouterAddress"}).Debug("Creating new RouterAddress")

	// Validate transport type is not empty
	if transportType == "" {
		return nil, oops.Errorf("transport type cannot be empty")
	}

	transportCost, err := createTransportCost(cost)
	if err != nil {
		return nil, err
	}

	if !expiration.IsZero() {
		log.WithFields(logger.Fields{
			"pkg":        "router_address",
			"func":       "NewRouterAddress",
			"expiration": expiration,
		}).Warn("RouterAddress expiration must be all zeros per spec; value ignored and serialized as zeros")
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
		"pkg":           "router_address",
		"func":          "NewRouterAddress",
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
		return ErrNilRouterAddress
	}
	if err := validateRouterAddressFields(ra); err != nil {
		return err
	}
	if err := ra.TransportOptions.Validate(); err != nil {
		return oops.Errorf("invalid transport options: %w", err)
	}
	return nil
}

// ValidatePublishable performs semantic validation on top of Validate.
// It rejects addresses that are structurally valid but would be refused by
// remote peers due to an unroutable host IP.
func (ra *RouterAddress) ValidatePublishable() error {
	if err := ra.Validate(); err != nil {
		return err
	}
	if ra.CheckOption(HOST_OPTION_KEY) && !ra.HasRoutableHost() {
		host := ""
		if hs := ra.HostString(); hs != nil {
			host, _ = hs.Data()
		}
		return oops.Errorf("%w: %q", ErrUnroutableHost, host)
	}
	return nil
}

// validateRouterAddressFields checks that all required RouterAddress fields
// are non-nil and non-empty.
func validateRouterAddressFields(ra *RouterAddress) error {
	if ra.TransportCost == nil {
		return ErrMissingTransportCost
	}
	if ra.ExpirationDate == nil {
		return ErrMissingExpirationDate
	}
	// Spec: "Routers MUST set this field to all zeros." Validate() is the strict
	// outbound self-check (the parse path only warns, per the "Inbound Parsing
	// vs. Outbound Publishing" policy), so a non-zero expiration is rejected
	// here: publishing it would fail signature verification on every other
	// router, which assumes zeros.
	if !isAllZeros(ra.ExpirationDate[:]) {
		return oops.Errorf("%w: publishing a RouterAddress with a non-zero expiration fails RouterInfo signature verification on the network", ErrNonZeroExpiration)
	}
	if len(ra.TransportType) == 0 {
		return ErrMissingTransportType
	}
	// Reject an empty transport_style. The spec types this field as
	// "transport_style :: String, 1-256 bytes", while the String Contents note
	// says "Length may be 0"; the two are ambiguous about whether a zero-length
	// transport_style is permitted. This library takes the field's own "1-256
	// bytes" as the governing bound and treats an empty style as invalid, since
	// a RouterAddress with no transport name is not meaningful. A transport_style
	// given as {0x00} has a raw length of 1 but declares zero content bytes, which
	// would pass the raw-length check above but fail round-trip parsing, so the
	// decoded content length is checked here.
	if content, err := ra.TransportType.Data(); err != nil || len(content) == 0 {
		return ErrEmptyTransportStyle
	}
	if ra.TransportOptions == nil {
		return ErrMissingTransportOptions
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
		log.WithFields(logger.Fields{"pkg": "router_address", "func": "createTransportCost"}).WithError(err).Error("Failed to create TransportCost Integer")
		return nil, err
	}
	return transportCost, nil
}

// createExpirationDate creates the ExpirationDate field as a Date.
// Per I2P spec (0.9.12+), the expiration MUST always be all zeros.
// The expiration parameter is accepted for API compatibility but is always ignored;
// the resulting Date is always all-zeros regardless of the value passed.
func createExpirationDate(expiration time.Time) (*data.Date, error) {
	_ = expiration                            // explicitly ignored per I2P spec — expiration is always all zeros
	dateBytes := make([]byte, data.DATE_SIZE) // all zeros per spec
	expirationDate, _, err := data.NewDate(dateBytes)
	if err != nil {
		log.WithFields(logger.Fields{"pkg": "router_address", "func": "createExpirationDate"}).WithError(err).Error("Failed to create ExpirationDate")
		return nil, err
	}
	return expirationDate, nil
}

// createTransportType creates the TransportType field as an I2PString.
// Returns error if the transport type string exceeds maximum size.
func createTransportType(transportType string) (data.I2PString, error) {
	transportTypeStr, err := data.ToI2PString(transportType)
	if err != nil {
		log.WithFields(logger.Fields{"pkg": "router_address", "func": "createTransportType"}).WithError(err).Error("Failed to create TransportType I2PString")
		return data.I2PString{}, err
	}
	return transportTypeStr, nil
}

// createTransportOptions creates the TransportOptions field as a Mapping.
// Returns error if the options map cannot be converted to a Mapping.
func createTransportOptions(options map[string]string) (*data.Mapping, error) {
	transportOptions, err := data.GoMapToMapping(options)
	if err != nil {
		log.WithFields(logger.Fields{"pkg": "router_address", "func": "createTransportOptions"}).WithError(err).Error("Failed to create TransportOptions Mapping")
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
