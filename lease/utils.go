// Package lease implements the I2P lease common data structure
package lease

import (
	"github.com/samber/oops"
	"github.com/sirupsen/logrus"
)

// ReadLease returns Lease from a []byte.
// The remaining bytes after the specified length are also returned.
// Returns a list of errors that occurred during parsing.
func ReadLease(data []byte) (lease Lease, remainder []byte, err error) {
	log.WithField("input_length", len(data)).Debug("Reading Lease from bytes")

	if len(data) < LEASE_SIZE {
		err = oops.Errorf("error parsing lease: not enough data")
		log.WithFields(logrus.Fields{
			"data_length":     len(data),
			"required_length": LEASE_SIZE,
		}).Error("Failed to read lease: insufficient data")
		return
	}

	copy(lease[:], data[:LEASE_SIZE])
	remainder = data[LEASE_SIZE:]

	log.WithFields(logrus.Fields{
		"tunnel_id":        lease.TunnelID(),
		"expiration":       lease.Date().Time(),
		"remainder_length": len(remainder),
	}).Debug("Successfully read Lease")

	return
}

// NewLeaseFromBytes creates a new *Lease from []byte using ReadLease.
// Returns a pointer to Lease unlike ReadLease.
func NewLeaseFromBytes(data []byte) (lease *Lease, remainder []byte, err error) {
	log.WithField("input_length", len(data)).Debug("Creating Lease from bytes")

	var l Lease
	l, remainder, err = ReadLease(data)
	if err != nil {
		log.WithError(err).Error("Failed to read Lease from bytes")
		return nil, remainder, err
	}

	lease = &l

	log.WithFields(logrus.Fields{
		"tunnel_id":        lease.TunnelID(),
		"expiration":       lease.Date().Time(),
		"remainder_length": len(remainder),
	}).Debug("Successfully created Lease from bytes")

	return
}
