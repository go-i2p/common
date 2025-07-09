// Package lease_set implements the I2P LeaseSet struct definition
package lease_set

/*
[LeaseSet]
Accurate for version 0.9.49

Description
Contains all of the currently authorized Leases for a particular Destination, the
publicKey to which garlic messages can be encrypted, and then the signingPublicKey
that can be used to revoke this particular version of the structure. The LeaseSet is one
of the two structures stored in the network database (the other being RouterInfo), and
is kered under the SHA256 of the contained Destination.

Contents
Destination, followed by a publicKey for encryption, then a signingPublicKey which
can be used to revoke this version of the LeaseSet, then a 1 byte Integer specifying how
many Lease structures are in the set, followed by the actual Lease structures and
finally a Signature of the previous bytes signed by the Destination's SigningPrivateKey.

+----+----+----+----+----+----+----+----+
| destination                           |
+                                       +
|                                       |
~                                       ~
~                                       ~
|                                       |
+----+----+----+----+----+----+----+----+
| encryption_key                        |
+                                       +
|                                       |
~                                       ~
~                                       ~
|                                       |
+----+----+----+----+----+----+----+----+
| signing_key                           |
+                                       +
|                                       |
~                                       ~
~                                       ~
|                                       |
+----+----+----+----+----+----+----+----+
|num | Lease 0                          |
+----+                                  +
|                                       |
~                                       ~
~                                       ~
|                                       |
+----+----+----+----+----+----+----+----+
| Lease 1                               |
+                                       +
|                                       |
~                                       ~
~                                       ~
|                                       |
+----+----+----+----+----+----+----+----+
| Lease ($num-1)                        |
+                                       +
|                                       |
~                                       ~
~                                       ~
|                                       |
+----+----+----+----+----+----+----+----+
| signature                             |
+                                       +
|                                       |
+                                       +
|                                       |
+                                       +
|                                       |
+                                       +
|                                       |
+----+----+----+----+----+----+----+----+

destination :: Destination
               length -> >= 387 bytes

encryption_key :: publicKey
                  length -> 256 bytes

signing_key :: signingPublicKey
               length -> 128 bytes or as specified in destination's key certificate

num :: Integer
       length -> 1 byte
       Number of leases to follow
       value: 0 <= num <= 16

leases :: [Lease]
          length -> $num*44 bytes

signature :: Signature
             length -> 40 bytes or as specified in destination's key certificate
*/

// LeaseSet is the represenation of an I2P LeaseSet.
//
// https://geti2p.net/spec/common-structures#leaseset
//
type LeaseSet []byte

/*
type LeaseSet struct {
	Destination *Destination
	EncryptionKey *crypto.ElgPublicKey
	SigningKey *crypto.ElgPublicKey
	Size *Integer
	Leases []*Lease
	Signature *Signature
}
*/
