package lease

import "errors"

// Errors
var (
	// ErrExpiredLease indicates a lease with an expiration time in the past.
	// Returned by Validate() when the lease has expired.
	ErrExpiredLease = errors.New("lease has expired")

	// ErrZeroGatewayHash indicates a lease with an all-zero tunnel gateway hash.
	// Returned by Validate() when the gateway hash is all zeros.
	ErrZeroGatewayHash = errors.New("tunnel gateway hash is zero")

	// ErrTimestampOverflow indicates a Lease2 expiration time exceeds the uint32 second range.
	// Lease2 uses 4-byte timestamps which overflow after 2106-02-07T06:28:15 UTC.
	ErrTimestampOverflow = errors.New("timestamp exceeds Lease2 uint32 range")

	// ErrPreEpochTimestamp indicates an expiration time before the Unix epoch (1970-01-01).
	// I2P timestamps are unsigned milliseconds/seconds since epoch; pre-epoch values
	// would wrap to extremely large unsigned values on the wire.
	ErrPreEpochTimestamp = errors.New("expiration time is before Unix epoch")

	// ErrNullDate indicates a lease with end_date = 0, which the I2P spec defines as
	// "undefined or null" (Date type definition). Distinct from ErrExpiredLease so
	// callers can handle null-date leases differently from merely-expired ones.
	ErrNullDate = errors.New("lease end_date is null (zero per I2P spec Date definition)")

	// ErrZeroTunnelID indicates a lease with tunnel ID 0.
	// The I2P spec states: "A Tunnel ID is generally greater than zero;
	// do not use a value of zero except in special cases."
	// Returned as an advisory by Validate().
	ErrZeroTunnelID = errors.New("tunnel ID is zero (spec recommends non-zero except in special cases)")
)
