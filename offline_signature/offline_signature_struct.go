// Package offline_signature implements the I2P OfflineSignature common data structure.
package offline_signature

/*
[OfflineSignature]
Accurate for version 0.9.67

+----+----+----+----+----+----+----+----+
|     expires       | sigtype |         |
+----+----+----+----+----+----+         +
|       transient_public_key            |
~                                       ~
~                                       ~
|                                       |
+----+----+----+----+----+----+----+----+
|           signature                   |
~                                       ~
~                                       ~
|                                       |
+----+----+----+----+----+----+----+----+

expires :: 4 byte date
           length -> 4 bytes
           Seconds since the epoch, rolls over in 2106.

sigtype :: 2 byte type of the transient_public_key
           length -> 2 bytes

transient_public_key :: SigningPublicKey
                        length -> As inferred from the sigtype

signature :: Signature
             length -> As inferred from the sigtype of the signing public key
                       in the Destination that preceded this offline signature.
             Signature of expires timestamp, transient sig type, and public key,
             by the destination public key.

Total minimum size: 102 bytes (with EdDSA keys)
Maximum size: varies based on signature types

https://geti2p.net/spec/common-structures#offlinesignature
*/

// OfflineSignature represents an I2P offline signature structure used in LeaseSet2,
// streaming, and I2CP protocols. It enables enhanced security by allowing destinations
// to use short-lived transient signing keys while keeping the long-term destination
// signing key offline.
//
// The structure contains:
//   - Expiration timestamp for the transient key
//   - Transient signing public key type and data
//   - Signature by the destination's long-term key proving authorization
//
// This structure can and should be generated offline for maximum security.
type OfflineSignature struct {
	expires            uint32 // 4-byte timestamp (seconds since epoch)
	sigtype            uint16 // 2-byte signature type of transient key
	transientPublicKey []byte // Variable length signing public key
	signature          []byte // Variable length signature by destination key
	destinationSigType uint16 // Signature type of the destination (for validation)
}
