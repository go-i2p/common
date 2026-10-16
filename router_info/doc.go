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
// receivers for compatibility with fmt.Stringer and net.Addr.
//
// Nil-safety is limited: Validate(), IsValid(), VerifySignature() and
// AddAddress() handle a nil *RouterInfo and return a descriptive error or zero
// value. All other methods — including the value-receiver serialization and
// net.Addr/fmt.Stringer methods — panic when called on a nil *RouterInfo. A
// zero-value or partially-parsed RouterInfo taken by pointer is safe: those
// cases return zero values or descriptive errors.
//
// # Signature Support
//
// Verification (VerifySignature) supports all modern signature types —
// Ed25519 (7), Ed25519ph (8), RedDSA (11), and ECDSA P256/P384/P521
// (1/2/3) — through the generic verifier interface. Creation
// (NewRouterInfo) currently supports Ed25519 (7) only; every other signing
// type fails with "unsupported signature type", and the signing private key
// must be an ed25519.PrivateKey. Legacy types (DSA-SHA1 and RSA) are rejected
// with an explicit "legacy unsupported" error, matching their deprecation in
// I2P 0.9.58. Parsing via ReadRouterInfo handles all signature types for
// correct field delineation.
//
// Spec reference: https://geti2p.net/spec/common-structures#routerinfo
package router_info
