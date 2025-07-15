// Package signature implements the I2P Signature common data structure
package signature

import (
	"fmt"

	"github.com/sirupsen/logrus"
)

/*
[Signature]
Accurate for version 0.9.49

Description
This structure represents the signature of some data.

Contents
Signature type and length are inferred from the type of key used. The default type is
DSA_SHA1. As of release 0.9.12, other types may be supported, depending on context.
*/

// Signature is the represenation of an I2P Signature.
//
// https://geti2p.net/spec/common-structures#signature
type Signature struct {
	// sigType holds the signature algorithm type
	sigType int
	// data holds the raw signature bytes
	data []byte
}

// NewSignature creates a new *Signature from []byte using ReadSignature.
// Returns a pointer to Signature unlike ReadSignature.
func NewSignature(data []byte, sigType int) (signature *Signature, remainder []byte, err error) {
	log.WithField("input_length", len(data)).Debug("Creating new Signature")
	sig, remainder, err := ReadSignature(data, sigType)
	if err != nil {
		log.WithError(err).Error("Failed to read Signature")
		return nil, remainder, err
	}
	signature = &sig
	log.WithFields(logrus.Fields{
		"signature_length": sig.Len(),
		"remainder_length": len(remainder),
	}).Debug("Successfully created new Signature")
	return
}

// NewSignatureFromBytes creates a Signature struct from raw bytes without type validation.
// This is used when the signature type is known but validation is not needed.
func NewSignatureFromBytes(data []byte, sigType int) Signature {
	return Signature{
		sigType: sigType,
		data:    data,
	}
}

// Type returns the signature algorithm type
func (s Signature) Type() int {
	return s.sigType
}

// Bytes returns the raw signature data as a byte slice for compatibility
func (s Signature) Bytes() []byte {
	return s.data
}

// Len returns the length of the signature data
func (s Signature) Len() int {
	return len(s.data)
}

// String returns a string representation of the signature type and length
func (s Signature) String() string {
	return fmt.Sprintf("Signature{type: %d, length: %d}", s.sigType, len(s.data))
}
