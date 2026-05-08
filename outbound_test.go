package anytls

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/protocol/socks/socks5"
)

func TestNewOutboundRejectsUnsupportedSchemes(t *testing.T) {
	cases := []string{
		"http://127.0.0.1:8080",
		"https://example.com",
		"socks4://127.0.0.1:1080",
		"socks4a://127.0.0.1:1080",
		"ftp://127.0.0.1",
	}
	for _, raw := range cases {
		t.Run(raw, func(t *testing.T) {
			if _, err := newOutbound(raw); err == nil {
				t.Fatalf("expected error for scheme in %q", raw)
			}
		})
	}
}

func TestNewOutboundRejectsMissingPieces(t *testing.T) {
	cases := map[string]string{
		"missing scheme": "127.0.0.1:1080",
		"missing host":   "socks5://",
		"empty":          "",
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := newOutbound(raw); err == nil {
				t.Fatalf("expected error for %q", raw)
			}
		})
	}
}

func TestNewOutboundAcceptsSocks5(t *testing.T) {
	for _, raw := range []string{
		"socks5://127.0.0.1:1080",
		"socks://127.0.0.1:1080",
		"socks5://user:pass@127.0.0.1:1080",
	} {
		t.Run(raw, func(t *testing.T) {
			if _, err := newOutbound(raw); err != nil {
				t.Fatalf("unexpected error for %q: %v", raw, err)
			}
		})
	}
}

func TestValidateRejectsBadUpstream(t *testing.T) {
	cases := map[string]string{
		"unsupported scheme": "http://127.0.0.1:8080",
		"missing host":       "socks5://",
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			lw := &ListenerWrapper{
				Users:    []User{{Name: "u", Password: "p", Enabled: true}},
				Upstream: raw,
			}
			if err := lw.Validate(); err == nil {
				t.Fatalf("Validate() = nil, want error for %q", raw)
			}
		})
	}
}

func TestUnmarshalCaddyfileUpstream(t *testing.T) {
	input := `anytls {
		user phone-1 secret
		upstream socks5://127.0.0.1:1080
	}`
	d := caddyfile.NewTestDispenser(input)
	lw := &ListenerWrapper{}
	if err := lw.UnmarshalCaddyfile(d); err != nil {
		t.Fatalf("UnmarshalCaddyfile() error = %v", err)
	}
	if lw.Upstream != "socks5://127.0.0.1:1080" {
		t.Fatalf("Upstream = %q, want %q", lw.Upstream, "socks5://127.0.0.1:1080")
	}
}

// TestOutboundRoutesTCPThroughSOCKS5 verifies that a TCP dial issued through
// outbound.DialContext actually traverses the configured SOCKS5 server.
func TestOutboundRoutesTCPThroughSOCKS5(t *testing.T) {
	// 1) Echo TCP server — final destination.
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen echo: %v", err)
	}
	defer echoLn.Close()
	go func() {
		for {
			c, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(c)
		}
	}()

	// 2) Minimal SOCKS5 CONNECT-only server.
	socksLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen socks: %v", err)
	}
	defer socksLn.Close()

	var srvWG sync.WaitGroup
	srvErr := make(chan error, 4)
	go func() {
		for {
			c, err := socksLn.Accept()
			if err != nil {
				return
			}
			srvWG.Add(1)
			go func(c net.Conn) {
				defer srvWG.Done()
				if err := serveSOCKS5Connect(c); err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
					srvErr <- err
				}
			}(c)
		}
	}()

	// 3) outbound configured against the SOCKS5 server.
	ob, err := newOutbound("socks5://" + socksLn.Addr().String())
	if err != nil {
		t.Fatalf("newOutbound: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := ob.DialContext(ctx, "tcp", echoLn.Addr().String())
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer conn.Close()

	const payload = "ping-via-socks5"
	if _, err := conn.Write([]byte(payload)); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != payload {
		t.Fatalf("echo mismatch: got %q want %q", buf, payload)
	}

	select {
	case err := <-srvErr:
		t.Fatalf("socks5 server error: %v", err)
	default:
	}
}

// serveSOCKS5Connect handles one SOCKS5 CONNECT request against conn. It uses
// sing's socks5 byte-level helpers so we don't reimplement RFC1928 framing.
func serveSOCKS5Connect(conn net.Conn) error {
	defer conn.Close()
	r := bufio.NewReader(conn)
	authReq, err := socks5.ReadAuthRequest(r)
	if err != nil {
		return err
	}
	_ = authReq
	if err := socks5.WriteAuthResponse(conn, socks5.AuthResponse{Method: socks5.AuthTypeNotRequired}); err != nil {
		return err
	}
	req, err := socks5.ReadRequest(r)
	if err != nil {
		return err
	}
	if req.Command != socks5.CommandConnect {
		return errors.New("only CONNECT supported in this test mock")
	}

	upstream, err := net.Dial("tcp", req.Destination.String())
	if err != nil {
		_ = socks5.WriteResponse(conn, socks5.Response{
			ReplyCode: socks5.ReplyCodeForError(err),
			Bind:      M.Socksaddr{},
		})
		return err
	}
	defer upstream.Close()

	if err := socks5.WriteResponse(conn, socks5.Response{
		ReplyCode: socks5.ReplyCodeSuccess,
		Bind:      M.SocksaddrFromNet(upstream.LocalAddr()),
	}); err != nil {
		return err
	}

	// Splice both directions until either side closes. Drain the buffered
	// reader's residue first so we don't lose any bytes the client may have
	// already pipelined after CONNECT.
	done := make(chan struct{}, 2)
	go func() {
		if buffered := r.Buffered(); buffered > 0 {
			if _, err := io.CopyN(upstream, r, int64(buffered)); err != nil {
				done <- struct{}{}
				return
			}
		}
		_, _ = io.Copy(upstream, conn)
		done <- struct{}{}
	}()
	go func() { _, _ = io.Copy(conn, upstream); done <- struct{}{} }()
	<-done
	return nil
}

// Sanity check that ParseSocksaddr round-trips through outbound dialing for
// IPv4 string addresses — guards against accidental "host:port" handling
// regressions if the dial path ever changes.
func TestOutboundParsesAddress(t *testing.T) {
	ob, err := newOutbound("socks5://127.0.0.1:1")
	if err != nil {
		t.Fatalf("newOutbound: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, err = ob.DialContext(ctx, "tcp", "203.0.113.5:443")
	if err == nil {
		t.Fatalf("expected dial to fail (no SOCKS5 server)")
	}
	// Sing reports the failure as "connect <addr>: ..." — we just want to
	// confirm the call path reaches the dialer rather than a parse panic.
	if strings.Contains(err.Error(), "panic") {
		t.Fatalf("unexpected panic-shaped error: %v", err)
	}
}
