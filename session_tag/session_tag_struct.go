// Package session_tag implements the I2P SessionTag common data structure
package session_tag

/*
[SessionTag]
Accurate for version 0.9.49

Description
A random number

Contents
32 bytes
*/

// SessionTag is the representation of an I2P SessionTag.
// A SessionTag is a 32-byte random number used in I2P for session identification.
//
// https://geti2p.net/spec/common-structures#session-tag
type SessionTag [SessionTagSize]byte
