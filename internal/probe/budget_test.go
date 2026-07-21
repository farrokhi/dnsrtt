package probe

import (
	"net/netip"
	"testing"
	"time"
)

func TestBudget(t *testing.T) {
	testCases := []struct {
		name string
		rtt  time.Duration
		want time.Duration
	}{{
		name: "fast_network_hits_floor",
		rtt:  15 * time.Millisecond,
		want: DefaultBudget,
	}, {
		name: "unmeasured_hits_floor",
		rtt:  0,
		want: DefaultBudget,
	}, {
		name: "just_below_floor",
		rtt:  800 * time.Millisecond,
		want: DefaultBudget,
	}, {
		name: "satellite_scales_up",
		rtt:  1900 * time.Millisecond,
		want: 11400 * time.Millisecond,
	}, {
		name: "pathological_hits_ceiling",
		rtt:  20 * time.Second,
		want: MaxBudget,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Budget(tc.rtt); got != tc.want {
				t.Errorf("Budget(%s) = %s, want %s", tc.rtt, got, tc.want)
			}
		})
	}
}

func TestPacketSize(t *testing.T) {
	v4 := netip.MustParseAddr("1.1.1.1")
	v6 := netip.MustParseAddr("2606:4700:4700::1111")

	testCases := []struct {
		name     string
		mtu      int
		ip       netip.Addr
		wantSize int
		wantOK   bool
	}{{
		name:     "tunnel_1280_v4",
		mtu:      1280,
		ip:       v4,
		wantSize: 1252, // 1280 - 28
		wantOK:   true,
	}, {
		name:     "ethernet_clamped_to_max",
		mtu:      1500,
		ip:       v4,
		wantSize: MaxDatagram,
		wantOK:   true,
	}, {
		name:     "exact_floor_v4",
		mtu:      MinDatagram + overhead4,
		ip:       v4,
		wantSize: MinDatagram,
		wantOK:   true,
	}, {
		name:   "below_floor_v4",
		mtu:    1000,
		ip:     v4,
		wantOK: false,
	}, {
		name:   "v6_needs_more_headroom",
		mtu:    MinDatagram + overhead4, // fits v4 but not v6
		ip:     v6,
		wantOK: false,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			size, ok := PacketSize(tc.mtu, tc.ip)
			if ok != tc.wantOK {
				t.Fatalf("PacketSize(%d) ok = %v, want %v", tc.mtu, ok, tc.wantOK)
			}

			if ok && size != tc.wantSize {
				t.Errorf("PacketSize(%d) = %d, want %d", tc.mtu, size, tc.wantSize)
			}
		})
	}
}
