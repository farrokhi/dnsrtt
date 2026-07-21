package probe

import (
	"errors"
	"net"
	"net/netip"
)

// MTU returns the link MTU of the interface that routes to ip.  Connecting a
// UDP socket performs a route lookup without sending anything, so the local
// address it picks identifies the egress interface.
func MTU(ip netip.Addr) (int, error) {
	conn, err := net.Dial("udp", net.JoinHostPort(ip.String(), "443"))
	if err != nil {
		return 0, err
	}
	defer func() { _ = conn.Close() }()

	local, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return 0, errors.New("not a udp local address")
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		return 0, err
	}

	for _, iface := range ifaces {
		addrs, aerr := iface.Addrs()
		if aerr != nil {
			continue
		}

		for _, a := range addrs {
			n, ok := a.(*net.IPNet)
			if ok && n.IP.Equal(local.IP) {
				return iface.MTU, nil
			}
		}
	}

	return 0, errors.New("no interface matches the egress address")
}
