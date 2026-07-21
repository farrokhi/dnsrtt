package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"syscall"
)

// wire is the L4 protocol and port a transport rides, used to phrase why it did
// not answer.
type wire struct {
	l4   string
	port int
}

var transportWire = map[string]wire{
	"Do53": {"udp", 53},
	"DoT":  {"tcp", 853},
	"DoH2": {"tcp", 443},
	"DoQ":  {"udp", 853},
	"DoH3": {"udp", 443},
}

// explain turns a transport's failure into a concise, honest reason.  A bare
// timeout cannot tell "server does not offer this" from "the port is filtered
// on this path", so the message says so rather than guessing.
func explain(label string, err error) string {
	w := transportWire[label]
	at := fmt.Sprintf("%s/%d", w.l4, w.port)
	text := err.Error()

	switch {
	case isTimeout(err):
		return fmt.Sprintf("no response on %s (server may not offer %s, or the port is blocked)", at, label)
	case errors.Is(err, syscall.ECONNREFUSED) || strings.Contains(text, "connection refused"):
		return fmt.Sprintf("connection refused on %s (server does not offer %s here)", at, label)
	case strings.Contains(strings.ToLower(text), "no application protocol"):
		return fmt.Sprintf("server does not offer %s (ALPN not accepted)", label)
	case strings.Contains(text, "x509") || strings.Contains(text, "certificate"):
		return "TLS certificate rejected"
	case strings.Contains(text, "unexpected status"):
		return "server returned " + strings.TrimPrefix(text, "unexpected status ") + " (no DoH here)"
	default:
		return text
	}
}

// isTimeout reports whether err is any flavor of "nothing came back in time":
// a context deadline, a net timeout, or the quic/http timeout strings that do
// not surface as a net.Error.
func isTimeout(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}

	var nerr net.Error
	if errors.As(err, &nerr) && nerr.Timeout() {
		return true
	}

	text := err.Error()
	for _, s := range []string{"no recent network activity", "Client.Timeout exceeded", "i/o timeout", "deadline exceeded"} {
		if strings.Contains(text, s) {
			return true
		}
	}

	return false
}
