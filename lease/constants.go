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
)

// Sizes in bytes of various components of a Lease according to I2P specification version 0.9.67
const (
	// LEASE_SIZE defines the total size of a complete I2P Lease structure in bytes.
	// A Lease consists of 32 bytes for tunnel gateway hash, 4 bytes for tunnel ID, and 8 bytes for end date.
	// This constant ensures consistent memory allocation and parsing across the I2P network.
	LEASE_SIZE = 44

	// LEASE_TUNNEL_GW_SIZE defines the size of the tunnel gateway hash field in bytes.
	// This field contains the SHA256 hash of the RouterIdentity of the gateway router,
	// providing secure identification of the tunnel endpoint for message routing.
	LEASE_TUNNEL_GW_SIZE = 32

	// LEASE_TUNNEL_ID_SIZE defines the size of the tunnel identifier field in bytes.
	// The tunnel ID is a 32-bit unsigned integer that uniquely identifies a specific tunnel
	// within the context of the gateway router for message forwarding.
	LEASE_TUNNEL_ID_SIZE = 4

	// LEASE2_SIZE defines the total size of a complete I2P Lease2 structure in bytes.
	// A Lease2 is a more compact version introduced in I2P specification 0.9.38 for LeaseSet2.
	// It consists of 32 bytes for tunnel gateway hash, 4 bytes for tunnel ID, and 4 bytes for end date.
	// This reduces the size from 44 bytes (Lease) to 40 bytes by using a 4-byte timestamp instead of 8-byte.
	LEASE2_SIZE = 40

	// LEASE2_END_DATE_SIZE defines the size of the end date field in Lease2 structures.
	// Unlike legacy Lease which uses 8-byte millisecond timestamps, Lease2 uses 4-byte second timestamps
	// for more efficient encoding in LeaseSet2 structures introduced in I2P specification 0.9.38.
	LEASE2_END_DATE_SIZE = 4

	// LEASE2_MAX_END_DATE is the maximum value for a Lease2 end_date field (uint32 max).
	// Corresponds to 2106-02-07T06:28:15 UTC.
	LEASE2_MAX_END_DATE = uint64(1<<32 - 1)
)
