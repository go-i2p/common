// Package signature implements the I2P Signature common data structure
package signature

import (
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
type Signature []byte

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
		"signature_length": len(sig),
		"remainder_length": len(remainder),
	}).Debug("Successfully created new Signature")
	return
}
