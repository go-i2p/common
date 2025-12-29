package router_info

import (
	"strings"

	"github.com/go-i2p/common/data"
)

// Check if any router addresses are reachable on IPv4
func (router_info *RouterInfo) HasIPv4() bool {
	for _, raddr := range router_info.RouterAddresses() {
		if raddr.IPVersion() == "4" {
			return true
		}
	}
	return false
}

// Check if any router addresses are reachable on IPv6
func (router_info *RouterInfo) HasIPv6() bool {
	for _, raddr := range router_info.RouterAddresses() {
		if raddr.IPVersion() == "6" {
			return true
		}
	}
	return false
}

// Check if a router is a FloodFill
func (router_info *RouterInfo) IsFloodfill() bool {
	// check for an `f` in the RI options
	f, err := data.NewI2PString("f")
	if err != nil {
		return false
	}
	opt := router_info.Options().Values().Get(f)
	if opt == nil {
		return false
	}
	return true
}

// Check if a RI supports NTCP2
func (router_info *RouterInfo) SupportsNTCP2() bool {
	for _, raddr := range router_info.RouterAddresses() {
		style := raddr.TransportStyle()
		txt, err := style.DataSafe()
		if err != nil {
			return false
		}
		txt = strings.ToLower(txt)
		if strings.Contains(txt, "ntcp2") {
			return true
		}
	}
	return false
}

// Check if a RI supports SSU2
func (router_info *RouterInfo) SupportsSSU2() bool {
	for _, raddr := range router_info.RouterAddresses() {
		style := raddr.TransportStyle()
		txt, err := style.DataSafe()
		if err != nil {
			return false
		}
		txt = strings.ToLower(txt)
		if strings.Contains(txt, "ntcp2") {
			return true
		}
	}
	return false
}
