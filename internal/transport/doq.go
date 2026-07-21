package transport

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"sync"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
)

// alpnDoQ is the ALPN token for DNS-over-QUIC (RFC 9250, section 4.1).
const alpnDoQ = "doq"

// DoQ is a DNS-over-QUIC client on a single reused connection.
type DoQ struct {
	cfg Config

	mu   sync.Mutex
	conn *quic.Conn

	redials
}

// NewDoQ returns a DoQ client for cfg.
func NewDoQ(cfg Config) *DoQ {
	return &DoQ{cfg: cfg}
}

// Address reports the human-readable upstream address.
func (u *DoQ) Address() string {
	return "quic://" + u.cfg.ServerName
}

// Close tears down the cached connection.
func (u *DoQ) Close() error {
	u.mu.Lock()
	defer u.mu.Unlock()

	if u.conn != nil {
		_ = u.conn.CloseWithError(0, "")
		u.conn = nil
	}

	return nil
}

// Exchange sends req over a new stream on the reused connection.
func (u *DoQ) Exchange(req *dns.Msg) (*dns.Msg, error) {
	ctx, cancel := context.WithTimeout(context.Background(), u.cfg.Timeout)
	defer cancel()

	conn, err := u.connection(ctx)
	if err != nil {
		return nil, err
	}

	resp, err := u.exchange(ctx, conn, req)
	if err != nil {
		// A stream error usually means the connection is gone; drop it so the
		// next call redials rather than reusing a dead conn.
		u.discard(conn)

		return nil, err
	}

	return resp, nil
}

// connection returns the cached connection, dialing a new one if needed.
func (u *DoQ) connection(ctx context.Context) (*quic.Conn, error) {
	u.mu.Lock()
	defer u.mu.Unlock()

	if u.conn != nil {
		return u.conn, nil
	}

	conn, err := quic.DialAddrEarly(
		ctx,
		u.cfg.Addr.String(),
		u.cfg.tlsConfig(alpnDoQ),
		u.cfg.quicConfig(),
	)
	if err != nil {
		return nil, fmt.Errorf("dialing quic to %s: %w", u.cfg.Addr, err)
	}

	u.conn = conn
	u.mark()

	return conn, nil
}

// discard drops conn if it is still the cached one.
func (u *DoQ) discard(conn *quic.Conn) {
	u.mu.Lock()
	defer u.mu.Unlock()

	if u.conn == conn {
		_ = conn.CloseWithError(0, "")
		u.conn = nil
	}
}

// exchange runs one query/response over a fresh stream.
func (u *DoQ) exchange(ctx context.Context, conn *quic.Conn, req *dns.Msg) (*dns.Msg, error) {
	packed, err := zeroID(req).Pack()
	if err != nil {
		return nil, fmt.Errorf("packing query: %w", err)
	}

	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, fmt.Errorf("opening stream: %w", err)
	}
	defer func() { _ = stream.Close() }()

	// RFC 9250, section 4.2: a 2-byte length prefix precedes the message, and
	// the client closes its send side after writing the single query.
	buf := make([]byte, 2+len(packed))
	binary.BigEndian.PutUint16(buf, uint16(len(packed)))
	copy(buf[2:], packed)

	if _, err = stream.Write(buf); err != nil {
		return nil, fmt.Errorf("writing query: %w", err)
	}
	_ = stream.Close()

	return readPrefixed(stream)
}

// readPrefixed reads a 2-byte length-prefixed DNS message from r.
func readPrefixed(r io.Reader) (*dns.Msg, error) {
	var length uint16
	if err := binary.Read(r, binary.BigEndian, &length); err != nil {
		return nil, fmt.Errorf("reading length: %w", err)
	}

	body := make([]byte, length)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, fmt.Errorf("reading body: %w", err)
	}

	resp := &dns.Msg{}
	if err := resp.Unpack(body); err != nil {
		return nil, fmt.Errorf("unpacking response: %w", err)
	}

	return resp, nil
}
