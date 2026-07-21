package probe

import (
	"net/netip"
	"time"
)

const (
	// RTTFactor scales a round trip into a query budget: an encrypted transport
	// spends two to three round trips on the handshake before the query, and
	// DoH3 must fit all of it inside one deadline.
	RTTFactor = 6

	// DefaultBudget is the floor and the fallback when no measurement is
	// available, leaving fast networks unaffected.
	DefaultBudget = 5 * time.Second

	// MaxBudget bounds a pathological measurement.
	MaxBudget = 60 * time.Second

	// MinDatagram is the UDP payload every QUIC endpoint must support
	// (RFC 9000, section 14.1).  A path that cannot carry it cannot carry QUIC.
	MinDatagram = 1200

	// MaxDatagram keeps initial packets inside a conventional 1500-byte link.
	MaxDatagram = 1452

	// overhead4 and overhead6 are the IP plus UDP headers wrapped around the
	// datagram, which is what makes a 1280-byte payload exceed a 1280 MTU.
	overhead4 = 20 + 8
	overhead6 = 40 + 8
)

// Overhead returns the per-packet IP and UDP header cost for the address
// family of ip.
func Overhead(ip netip.Addr) int {
	if ip.Is6() && !ip.Is4In6() {
		return overhead6
	}

	return overhead4
}

// PacketSize converts a path MTU into the QUIC initial packet size, clamped to
// what the protocol allows.  Returns false when the path cannot carry QUIC at
// all, so the caller can say so instead of waiting for a black hole to time
// out.
func PacketSize(mtu int, ip netip.Addr) (size int, ok bool) {
	payload := mtu - Overhead(ip)
	if payload < MinDatagram {
		return 0, false
	}

	if payload > MaxDatagram {
		payload = MaxDatagram
	}

	return payload, true
}

// Budget converts a measured round-trip time into a per-query timeout, clamped
// to [DefaultBudget, MaxBudget].
func Budget(rtt time.Duration) time.Duration {
	d := time.Duration(RTTFactor) * rtt

	switch {
	case d < DefaultBudget:
		return DefaultBudget
	case d > MaxBudget:
		return MaxBudget
	default:
		return d
	}
}
