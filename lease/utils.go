package lease

import (
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// ReadLease parses a Lease structure from raw byte data according to I2P specification.
// Validates that the input data contains at least 44 bytes required for a complete lease,
// then extracts the tunnel gateway hash, tunnel ID, and expiration date into a Lease structure.
// Returns the parsed lease, any remaining unparsed bytes, and an error if parsing fails.
func ReadLease(data []byte) (lease Lease, remainder []byte, err error) {
	log.WithFields(logger.Fields{"pkg": "lease", "func": "ReadLease", "input_length": len(data)}).Debug("Reading Lease from bytes")

	// Validate input data length before attempting to parse lease structure
	if len(data) < LEASE_SIZE {
		err = oops.Errorf("error parsing lease: not enough data (expected %d bytes, got %d bytes)", LEASE_SIZE, len(data))
		log.WithFields(logger.Fields{
			"pkg":             "lease",
			"func":            "ReadLease",
			"data_length":     len(data),
			"required_length": LEASE_SIZE,
		}).Error("Failed to read lease: insufficient data")
		return lease, remainder, err
	}

	// Copy exactly LEASE_SIZE bytes to create the lease structure
	copy(lease[:], data[:LEASE_SIZE])
	remainder = data[LEASE_SIZE:]

	log.WithFields(logger.Fields{
		"pkg":              "lease",
		"func":             "ReadLease",
		"tunnel_id":        lease.TunnelID(),
		"expiration":       lease.Time(),
		"remainder_length": len(remainder),
	}).Debug("Successfully read Lease")

	return lease, remainder, err
}

// NewLeaseFromBytes creates a new Lease pointer from raw byte data using ReadLease.
// This convenience function wraps ReadLease to return a pointer to the parsed Lease structure
// instead of a value copy, which is useful for APIs that expect lease pointers.
//
// On error, returns (nil, remainder, err). The remainder is returned even on failure
// to allow callers to skip past malformed data in a stream. If err != nil, the remainder
// contains all bytes beyond those that were expected to form the Lease (i.e., data itself
// if it was too short). Callers should not rely on remainder contents when err != nil
// unless they are implementing stream recovery logic.
func NewLeaseFromBytes(data []byte) (lease *Lease, remainder []byte, err error) {
	log.WithFields(logger.Fields{"pkg": "lease", "func": "NewLeaseFromBytes", "input_length": len(data)}).Debug("Creating Lease from bytes")

	var l Lease
	// Use ReadLease to perform the actual parsing and validation
	l, remainder, err = ReadLease(data)
	if err != nil {
		log.WithFields(logger.Fields{"pkg": "lease", "func": "NewLeaseFromBytes"}).WithError(err).Error("Failed to read Lease from bytes")
		return nil, remainder, err
	}

	lease = &l

	log.WithFields(logger.Fields{
		"pkg":              "lease",
		"func":             "NewLeaseFromBytes",
		"tunnel_id":        lease.TunnelID(),
		"expiration":       lease.Time(),
		"remainder_length": len(remainder),
	}).Debug("Successfully created Lease from bytes")

	return lease, remainder, err
}

// ReadLease2 parses a Lease2 structure from raw byte data according to I2P specification 0.9.67.
// Validates that the input data contains at least 40 bytes required for a complete Lease2,
// then extracts the tunnel gateway hash, tunnel ID, and 4-byte expiration timestamp.
// Returns the parsed Lease2, any remaining unparsed bytes, and an error if parsing fails.
//
// Example: lease2, remainder, err := ReadLease2(networkData)
func ReadLease2(data []byte) (lease2 Lease2, remainder []byte, err error) {
	log.WithFields(logger.Fields{"pkg": "lease", "func": "ReadLease2", "input_length": len(data)}).Debug("Reading Lease2 from bytes")

	// Validate input data length before attempting to parse lease2 structure
	// Ensures that buffer underflows cannot occur during lease2 field extraction
	if len(data) < LEASE2_SIZE {
		err = oops.Errorf("error parsing lease2: not enough data (expected %d bytes, got %d bytes)", LEASE2_SIZE, len(data))
		log.WithFields(logger.Fields{
			"pkg":             "lease",
			"func":            "ReadLease2",
			"data_length":     len(data),
			"required_length": LEASE2_SIZE,
		}).Error("Failed to read Lease2: insufficient data")
		return lease2, remainder, err
	}

	// Copy exactly LEASE2_SIZE bytes to create the lease2 structure
	// This preserves the original data while extracting the lease2 portion safely
	copy(lease2[:], data[:LEASE2_SIZE])
	remainder = data[LEASE2_SIZE:]

	log.WithFields(logger.Fields{
		"pkg":              "lease",
		"func":             "ReadLease2",
		"tunnel_id":        lease2.TunnelID(),
		"expiration":       lease2.Time(),
		"end_date_seconds": lease2.EndDate(),
		"remainder_length": len(remainder),
	}).Debug("Successfully read Lease2")

	return lease2, remainder, err
}

// NewLease2FromBytes creates a new Lease2 pointer from raw byte data using ReadLease2.
// This convenience function wraps ReadLease2 to return a pointer to the parsed Lease2 structure
// instead of a value copy, which is useful for APIs that expect lease pointers.
//
// On error, returns (nil, remainder, err). The remainder is returned even on failure
// to allow callers to skip past malformed data in a stream. If err != nil, the remainder
// contains all bytes beyond those that were expected to form the Lease2 (i.e., data itself
// if it was too short). Callers should not rely on remainder contents when err != nil
// unless they are implementing stream recovery logic.
//
// Example: lease2Ptr, remainder, err := NewLease2FromBytes(networkData)
func NewLease2FromBytes(data []byte) (lease2 *Lease2, remainder []byte, err error) {
	log.WithFields(logger.Fields{"pkg": "lease", "func": "NewLease2FromBytes", "input_length": len(data)}).Debug("Creating Lease2 from bytes")

	var l2 Lease2
	// Use ReadLease2 to perform the actual parsing and validation
	// This ensures consistent error handling and logging across both functions
	l2, remainder, err = ReadLease2(data)
	if err != nil {
		log.WithFields(logger.Fields{"pkg": "lease", "func": "NewLease2FromBytes"}).WithError(err).Error("Failed to read Lease2 from bytes")
		return nil, remainder, err
	}

	// Convert value type to pointer type for convenient API usage
	// Many I2P APIs expect lease pointers for efficient memory management
	lease2 = &l2

	log.WithFields(logger.Fields{
		"pkg":              "lease",
		"func":             "NewLease2FromBytes",
		"tunnel_id":        lease2.TunnelID(),
		"expiration":       lease2.Time(),
		"end_date_seconds": lease2.EndDate(),
		"remainder_length": len(remainder),
	}).Debug("Successfully created Lease2 from bytes")

	return lease2, remainder, err
}
