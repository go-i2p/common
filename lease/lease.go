// Package lease implements the I2P Lease common data structure according to specification version 0.9.67.
//
// ADDED: A Lease defines the authorization for a particular tunnel to receive messages targeting a Destination.
// Each lease contains the SHA256 hash of the RouterIdentity of the gateway router, the tunnel identifier,
// and an expiration date that determines when the lease becomes invalid for message delivery.
//
// ADDED: The lease structure is fundamental to I2P's tunnel-based message routing system, enabling secure
// and anonymous communication by providing time-limited authorization for tunnel message delivery.
// Leases are included in LeaseSet structures that are distributed throughout the I2P network database.
//
// ADDED: Key features:
//   - 44-byte fixed-length structure for efficient network transmission
//   - SHA256 tunnel gateway identification for secure routing
//   - 32-bit tunnel ID for precise tunnel selection within gateway routers
//   - Millisecond-precision expiration timestamps for fine-grained lease management
//   - Complete I2P specification compliance for network interoperability
//
// ADDED: Common usage patterns:
//
//	lease, err := NewLease(gatewayHash, tunnelID, expirationTime)
//	leaseData, remainder, err := ReadLease(networkBytes)
//	gatewayHash := lease.TunnelGateway()
//	tunnelID := lease.TunnelID()
//	expirationDate := lease.Date()
package lease
