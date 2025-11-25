package data

import (
	"crypto/sha256"
	"fmt"
	"io"

	"github.com/samber/oops"
)

/*
[I2P Hash]
Accurate for version 0.9.67

Description
Represents the SHA256 of some data.

Contents
32 bytes
*/

// Hash is the represenation of an I2P Hash.
//
// https://geti2p.net/spec/common-structures#hash
type Hash [32]byte

// ZeroHash represents an all-zeros hash (not a valid SHA256 of any data).
var ZeroHash = Hash{}

// Bytes returns the raw []byte content of a Hash.
func (h Hash) Bytes() [32]byte {
	return h
}

// NewHash creates a Hash from a 32-byte array.
// This is the preferred way to construct a Hash from known bytes.
func NewHash(hashBytes [32]byte) Hash {
	return Hash(hashBytes)
}

// NewHashFromSlice creates a Hash from a byte slice with validation.
// Returns error if the slice is not exactly 32 bytes.
func NewHashFromSlice(data []byte) (Hash, error) {
	if len(data) != 32 {
		return Hash{}, oops.Errorf("hash must be 32 bytes, got %d", len(data))
	}
	var h Hash
	copy(h[:], data)
	return h, nil
}

// IsZero returns true if the hash is all zeros.
// Note: This is not the same as the SHA256 of empty data.
func (h Hash) IsZero() bool {
	return h == ZeroHash
}

// Equal returns true if two hashes are identical.
func (h Hash) Equal(other Hash) bool {
	return h == other
}

// String returns the hash as a hexadecimal string for debugging.
func (h Hash) String() string {
	return fmt.Sprintf("%x", h[:])
}

// ReadHash reads a 32-byte hash from data and returns remaining bytes.
func ReadHash(data []byte) (Hash, []byte, error) {
	if len(data) < 32 {
		return Hash{}, data, oops.Errorf("insufficient data for hash: got %d bytes, need 32", len(data))
	}
	var h Hash
	copy(h[:], data[:32])
	return h, data[32:], nil
}

// HashData returns the SHA256 sum of a []byte input as Hash.
func HashData(data []byte) (h Hash) {
	// log.Println("Hashing Data:", data)
	h = sha256.Sum256(data)
	return
}

// HashReader returns the SHA256 sum from all data read from an io.Reader.
// return error if one occurs while reading from reader
func HashReader(r io.Reader) (h Hash, err error) {
	sha := sha256.New()
	_, err = io.Copy(sha, r)
	if err == nil {
		d := sha.Sum(nil)
		copy(h[:], d)
	}
	return
}
