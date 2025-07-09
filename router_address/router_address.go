// Package router_address implements the I2P RouterAddress common data structure
package router_address

import (
	"net"

	"github.com/go-i2p/logger"
)

var log = logger.GetGoI2PLogger()

// ex_addr is a package-level variable used to verify RouterAddress implements net.Addr
var ex_addr net.Addr = &RouterAddress{}
