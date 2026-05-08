package anytls

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strings"

	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/protocol/socks"
)

// outbound routes anytls outbound traffic through an upstream proxy. v1 only
// supports SOCKS5: TCP via CONNECT, UDP via UDP ASSOCIATE. Upstream lifecycle
// (the SOCKS5 TCP control connection) is owned by the per-request conn returned
// from DialContext / ListenPacket and torn down when that conn is closed.
type outbound struct {
	client *socks.Client
}

// newOutbound parses rawURL and constructs a SOCKS5 outbound. It rejects any
// scheme other than socks/socks5 so that operators get a clear error instead
// of a partially-working configuration.
func newOutbound(rawURL string) (*outbound, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("parse upstream URL: %w", err)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("upstream URL missing host")
	}
	switch strings.ToLower(u.Scheme) {
	case "socks", "socks5":
	case "":
		return nil, fmt.Errorf("upstream URL missing scheme")
	default:
		return nil, fmt.Errorf("unsupported upstream scheme %q (supported: socks5)", u.Scheme)
	}

	client, err := socks.NewClientFromURL(N.SystemDialer, rawURL)
	if err != nil {
		return nil, fmt.Errorf("build SOCKS5 client: %w", err)
	}
	return &outbound{client: client}, nil
}

// DialContext satisfies the dialFunc contract used by directTCPHandler: it
// receives "tcp" as the network and a "host:port" string as the address.
func (o *outbound) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	addr := M.ParseSocksaddr(address)
	return o.client.DialContext(ctx, network, addr)
}

// ListenPacket satisfies the listenPacketFunc contract. The address arg is
// always "" today, so we pass a zero Socksaddr — SOCKS5 servers commonly
// accept this (it means "I will use whatever local UDP port the server
// allocates", per RFC 1928 §6).
func (o *outbound) ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error) {
	var local M.Socksaddr
	if address != "" {
		local = M.ParseSocksaddr(address)
	}
	return o.client.ListenPacket(ctx, local)
}
