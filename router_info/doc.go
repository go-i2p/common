// Package router_info implements the I2P RouterInfo common data structure.
//
// RouterInfo is one of two structures stored in the I2P network database
// (the other being LeaseSet). It is keyed under the SHA256 of the contained
// RouterIdentity and defines all of the data that a router wants to publish
// for the network to see.
//
// A RouterInfo contains:
//   - RouterIdentity: the router's identity (keys + certificate)
//   - Published: the date when the entry was published
//   - Addresses: zero or more RouterAddress structures (transport endpoints)
//   - Options: a key=value Mapping with router metadata (version, capabilities, etc.)
//   - Signature: a cryptographic signature covering all preceding fields
//
// # Creation
//
// Use NewRouterInfo() to construct a signed RouterInfo:
//
//	ri, err := router_info.NewRouterInfo(identity, time.Now(), addresses, options, privKey, sigType)
//
// # Parsing
//
// Use ReadRouterInfo() to parse from bytes:
//
//	ri, remainder, err := router_info.ReadRouterInfo(data)
//
// # Capabilities
//
// RouterInfo exposes I2P capability letters via RouterCapabilities() and
// convenience methods such as IsFloodfill(), UnCongested(), Reachable(),
// SharedBandwidthCategory(), and the individual bandwidth tier methods.
//
// # Receiver Conventions
//
// Methods that read data use pointer receivers (*RouterInfo). Serialization and
// interface methods (Bytes, String, Options, Signature, Network) use value
// receivers for compatibility with fmt.Stringer and net.Addr. Both sets of
// methods are nil-safe — they return zero values or descriptive errors when
// called on uninitialized or partially-parsed RouterInfo.
//
// # Signature Support
//
// Currently, only Ed25519 (signature type 7) is supported for both creation
// (NewRouterInfo) and verification (VerifySignature). Parsing via ReadRouterInfo
// handles all signature types for correct field delineation, but cryptographic
// verification of legacy types (DSA-SHA1, ECDSA, RSA) is not yet implemented.
//
// Spec reference: https://geti2p.net/spec/common-structures#routerinfo
package router_info
