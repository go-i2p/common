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
	return strings.Contains(router_info.RouterCapabilities(), "f")
}

// IsMediumCongested checks if the router indicates medium congestion.
// Per the I2P spec, the "D" capability letter signals medium congestion
// (mnemonic: "Don't please").
func (router_info *RouterInfo) IsMediumCongested() bool {
	caps := router_info.RouterCapabilities()
	if strings.Contains(caps, "D") { // Mnemonic: "D"=="Don't please"
		return true
	}
	return false
}

// IsHighCongested checks if the router indicates high congestion.
// Per the I2P spec, the "E" capability letter signals high congestion
// (mnemonic: "Everyone stay away").
func (router_info *RouterInfo) IsHighCongested() bool {
	caps := router_info.RouterCapabilities()
	if strings.Contains(caps, "E") { // Mnemonic: "E"=="Everyone stay away"
		return true
	}
	return false
}

// IsRejectingTunnels checks if the router is rejecting tunnel build requests.
// Per the I2P spec, the "G" capability letter signals tunnel rejection
// (mnemonic: "Go away, no tunnels").
func (router_info *RouterInfo) IsRejectingTunnels() bool {
	caps := router_info.RouterCapabilities()
	if strings.Contains(caps, "G") { // Mnemonic: "G"=="Go away, no tunnels"
		return true
	}
	return false
}

// SharedBandwidthCategory returns the bandwidth capability letter for this router.
// Per the I2P spec, the bandwidth tiers are:
//   - K: Under 12 KBps shared bandwidth
//   - L: 12-48 KBps shared bandwidth
//   - M: 48-64 KBps shared bandwidth
//   - N: 64-128 KBps shared bandwidth
//   - O: 128-256 KBps shared bandwidth
//   - P: 256-2000 KBps shared bandwidth
//   - X: Over 2000 KBps (unlimited) shared bandwidth
//
// Returns an empty string if no bandwidth capability is present.
func (router_info *RouterInfo) SharedBandwidthCategory() string {
	caps := router_info.RouterCapabilities()
	for _, c := range caps {
		if strings.Contains("KLMNOPX", string(c)) {
			return string(c)
		}
	}
	return ""
}

// IsLowBandwidthRouter returns true if the router's shared bandwidth tier is "L" (12-48 KBps).
func (router_info *RouterInfo) IsLowBandwidthRouter() bool {
	return router_info.SharedBandwidthCategory() == "L"
}

// IsMediumLowBandwidthRouter returns true if the router's shared bandwidth tier is "M" (48-64 KBps).
func (router_info *RouterInfo) IsMediumLowBandwidthRouter() bool {
	return router_info.SharedBandwidthCategory() == "M"
}

// IsMediumBandwidthRouter returns true if the router's shared bandwidth tier is "N" (64-128 KBps).
func (router_info *RouterInfo) IsMediumBandwidthRouter() bool {
	return router_info.SharedBandwidthCategory() == "N"
}

// IsMediumHighBandwidthRouter returns true if the router's shared bandwidth tier is "O" (128-256 KBps).
func (router_info *RouterInfo) IsMediumHighBandwidthRouter() bool {
	return router_info.SharedBandwidthCategory() == "O"
}

// IsHighBandwidthRouter returns true if the router's shared bandwidth tier is "P" (256-2000 KBps).
func (router_info *RouterInfo) IsHighBandwidthRouter() bool {
	return router_info.SharedBandwidthCategory() == "P"
}

// IsUnlimitedBandwidthRouter returns true if the router's shared bandwidth tier is "X" (over 2000 KBps).
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
		if strings.Contains(txt, "ssu2") {
			return true
		}
	}
	return false
}
