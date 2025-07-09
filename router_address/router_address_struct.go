// Package router_address implements the I2P RouterAddress common data structure
package router_address

import (
	. "github.com/go-i2p/common/data"
)

/*
[RouterAddress]
Accurate for version 0.9.49

Description
This structure defines the means to contact a router through a transport protocol.

Contents
1 byte Integer defining the relative cost of using the address, where 0 is free and 255 is
expensive, followed by the expiration Date after which the address should not be used,
of if null, the address never expires. After that comes a String defining the transport
protocol this router address uses. Finally there is a Mapping containing all of the
transport specific options necessary to establish the connection, such as IP address,
port number, email address, URL, etc.


+----+----+----+----+----+----+----+----+
|cost|           expiration
+----+----+----+----+----+----+----+----+
     |        transport_style           |
+----+----+----+----+-//-+----+----+----+
|                                       |
+                                       +
|               options                 |
~                                       ~
~                                       ~
|                                       |
+----+----+----+----+----+----+----+----+

cost :: Integer
        length -> 1 byte

        case 0 -> free
        case 255 -> expensive

expiration :: Date (must be all zeros, see notes below)
              length -> 8 bytes

              case null -> never expires

transport_style :: String
                   length -> 1-256 bytes

options :: Mapping
*/

// RouterAddress is the represenation of an I2P RouterAddress.
//
// https://geti2p.net/spec/common-structures#routeraddress
type RouterAddress struct {
	TransportCost    *Integer
	ExpirationDate   *Date
	TransportType    I2PString
	TransportOptions *Mapping
}
