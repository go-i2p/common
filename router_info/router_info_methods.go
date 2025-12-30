package router_info

import (
	"strings"
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
	caps := router_info.RouterCapabilities()
	if !strings.Contains(caps, "f") {
		return false
	}
	return true
}

func (router_info *RouterInfo) IsMediumCongested() bool {
	caps := router_info.RouterCapabilities()
	if strings.Contains(caps, "D") { // Mnemonic: "D"=="Don't please"
		return true
	}
	return false
}

func (router_info *RouterInfo) IsHighCongested() bool {
	caps := router_info.RouterCapabilities()
	if strings.Contains(caps, "E") { // Mnemonic: "E"=="Everyone stay away"
		return true
	}
	return false
}

func (router_info *RouterInfo) IsRejectingTunnels() bool {
	caps := router_info.RouterCapabilities()
	if strings.Contains(caps, "G") { // Mnemonic: "G"=="Go away, no tunnels"
		return true
	}
	return false
}

/*
K: Under 12 KBps shared bandwidth
L: 12 - 48 KBps shared bandwidth (default)
M: 48 - 64 KBps shared bandwidth
N: 64 - 128 KBps shared bandwidth
O: 128 - 256 KBps shared bandwidth
P: 256 - 2000 KBps shared bandwidth (as of release 0.9.20, see note below)
X: Over 2000 KBps shared bandwidth
*/
func (router_info *RouterInfo) SharedBandwidthCategory() string {
	caps := router_info.RouterCapabilities()
	for _, c := range caps {
		if strings.Contains("KLMNOPX", string(c)) {
			return string(c)
		}
	}
	return ""
}

func (router_info *RouterInfo) IsLowBandwidthRouter() bool {
	return router_info.SharedBandwidthCategory() == "L"
}

func (router_info *RouterInfo) IsMediumLowBandwidthRouter() bool {
	return router_info.SharedBandwidthCategory() == "M"
}

func (router_info *RouterInfo) IsMediumBandwidthRouter() bool {
	return router_info.SharedBandwidthCategory() == "N"
}

func (router_info *RouterInfo) IsMediumHighBandwidthRouter() bool {
	return router_info.SharedBandwidthCategory() == "O"
}

func (router_info *RouterInfo) IsHighBandwidthRouter() bool {
	return router_info.SharedBandwidthCategory() == "P"
}

func (router_info *RouterInfo) IsUnlimitedBandwidthRouter() bool {
	return router_info.SharedBandwidthCategory() == "X"
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
