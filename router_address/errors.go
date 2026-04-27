// Package router_address implements the I2P RouterAddress common data structure
package router_address

import "errors"

// Sentinel errors for the router_address package.
// These allow callers to use errors.Is for programmatic error handling.
var (
	// ErrNilRouterAddress is returned when a nil RouterAddress is used.
	ErrNilRouterAddress = errors.New("router address is nil")

	// ErrNoData is returned when no data is provided to ReadRouterAddress.
	ErrNoData = errors.New("error parsing RouterAddress: no data")

	// ErrDataTooSmall is returned when the data is shorter than ROUTER_ADDRESS_MIN_SIZE.
	ErrDataTooSmall = errors.New("error parsing RouterAddress: data too small")

	// ErrMissingTransportCost is returned when TransportCost is nil.
	ErrMissingTransportCost = errors.New("transport cost is required")

	// ErrMissingExpirationDate is returned when ExpirationDate is nil.
	ErrMissingExpirationDate = errors.New("expiration date is required")

	// ErrMissingTransportType is returned when TransportType is nil or empty.
	ErrMissingTransportType = errors.New("transport type is required")

	// ErrEmptyTransportStyle is returned when the transport_style I2PString is zero-length.
	ErrEmptyTransportStyle = errors.New("transport style is empty")

	// ErrMissingTransportOptions is returned when TransportOptions is nil.
	ErrMissingTransportOptions = errors.New("transport options are required")

	// ErrMissingHost is returned when the host option is missing.
	ErrMissingHost = errors.New("missing required 'host' option")

	// ErrInvalidHost is returned when the host option is not a valid IP address.
	ErrInvalidHost = errors.New("invalid host IP address")

	// ErrUnroutableHost is returned when the host option contains a parseable but
	// non-routable IP address such as an unspecified, loopback, or link-local address.
	ErrUnroutableHost = errors.New("host address is not routable")

	// ErrMissingPort is returned when the port option is missing.
	ErrMissingPort = errors.New("missing required 'port' option")

	// ErrInvalidPort is returned when the port option is not a valid number in range 1-65535.
	ErrInvalidPort = errors.New("invalid port number")

	// ErrMissingStaticKey is returned when the static key ("s") option is not found.
	ErrMissingStaticKey = errors.New("static key not found")

	// ErrInvalidStaticKey is returned when the static key has an invalid length.
	ErrInvalidStaticKey = errors.New("invalid static key length")

	// ErrMissingInitializationVector is returned when the IV ("i") option is not found.
	ErrMissingInitializationVector = errors.New("initialization vector not found")

	// ErrInvalidInitializationVector is returned when the IV has an invalid length.
	ErrInvalidInitializationVector = errors.New("invalid initialization vector length")

	// ErrNonZeroExpiration is returned or indicated when the expiration field is non-zero.
	// Per the I2P spec (0.9.12+), routers MUST set this field to all zeros.
	ErrNonZeroExpiration = errors.New("non-zero expiration field")
)
