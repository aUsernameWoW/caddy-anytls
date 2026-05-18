// Package anytls implements a Caddy listener wrapper that detects AnyTLS
// connections after TLS termination and falls back to the normal site path
// for non-AnyTLS traffic.
package anytls

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	singanytls "github.com/anytls/sing-anytls"
	"github.com/anytls/sing-anytls/padding"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/uot"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(ListenerWrapper{})
}

// ListenerWrapper is a Caddy listener wrapper that peeks decrypted bytes to
// decide whether the connection should be handled as AnyTLS or returned to the
// normal website path.
type ListenerWrapper struct {
	Users               []User         `json:"users,omitempty"`
	ProbeTimeout        caddy.Duration `json:"probe_timeout,omitempty"`
	IdleTimeout         caddy.Duration `json:"idle_timeout,omitempty"`
	ConnectTimeout      caddy.Duration `json:"connect_timeout,omitempty"`
	MaxConcurrent       int            `json:"max_concurrent,omitempty"`
	Fallback            *bool          `json:"fallback,omitempty"`
	AllowPrivateTargets bool           `json:"allow_private_targets,omitempty"`
	PaddingScheme       string         `json:"padding_scheme,omitempty"`
	// Upstream, if set, routes all outbound TCP and UDP through a proxy
	// instead of dialing directly. Only socks5:// (and socks://) is supported
	// in v1 — both TCP CONNECT and UDP ASSOCIATE go through the same upstream.
	Upstream string `json:"upstream,omitempty"`
	// PassthroughUoT, when true (and Upstream is socks5://), forwards the
	// sing UoT magic-address CONNECT verbatim to the upstream instead of
	// decoding it into real UDP locally. Useful when the upstream is itself
	// UoT-aware (e.g. sing-box): it terminates the UoT framing and observes
	// the UDP, so this side does no UDP ASSOCIATE and the SOCKS5-UDP
	// domain-ATYP interop surface disappears. Trade-off: the upstream only
	// sees an opaque CONNECT to the magic address, so per-datagram UDP audit
	// on the upstream is bypassed. Defaults to off — clean installs and the
	// default decode path are unaffected.
	PassthroughUoT bool `json:"passthrough_uot,omitempty"`

	logger           *zap.Logger
	active           int64
	connSeq          uint64
	registry         *sessionRegistry
	detector         Detector
	service          *singanytls.Service
	websiteConns     *sync.Map
	dialFunc         func(ctx context.Context, network string, address string) (net.Conn, error)
	listenPacketFunc func(ctx context.Context, network string, address string) (net.PacketConn, error)
}

// User defines one AnyTLS account.
type User struct {
	Name     string `json:"name,omitempty"`
	Password string `json:"password,omitempty"`
	Enabled  bool   `json:"enabled,omitempty"`
}

// CaddyModule returns the Caddy module information.
func (ListenerWrapper) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "caddy.listeners.anytls",
		New: func() caddy.Module { return new(ListenerWrapper) },
	}
}

// Provision sets defaults and runtime dependencies.
func (lw *ListenerWrapper) Provision(ctx caddy.Context) error {
	lw.logger = ctx.Logger(lw)

	if lw.ProbeTimeout == 0 {
		lw.ProbeTimeout = caddy.Duration(5 * time.Second)
	}
	if lw.IdleTimeout == 0 {
		lw.IdleTimeout = caddy.Duration(2 * time.Minute)
	}
	if lw.ConnectTimeout == 0 {
		lw.ConnectTimeout = caddy.Duration(10 * time.Second)
	}
	if lw.MaxConcurrent == 0 {
		lw.MaxConcurrent = 128
	}
	if lw.Fallback == nil {
		enabled := true
		lw.Fallback = &enabled
	}
	if lw.PaddingScheme == "" {
		lw.PaddingScheme = string(padding.DefaultPaddingScheme)
	}
	if lw.registry == nil {
		lw.registry = newSessionRegistry()
	}
	if lw.websiteConns == nil {
		lw.websiteConns = &sync.Map{}
	}
	if server, ok := ctx.Context.Value(caddyhttp.ServerCtxKey).(*caddyhttp.Server); ok && server != nil {
		server.RegisterConnContext(lw.websiteConnContext)
		server.RegisterConnState(lw.cleanupWebsiteConn)
	}
	ctx.OnCancel(func() {
		lw.closeActiveSessions("config_unload")
	})

	lw.detector = NewPasswordHashDetector(lw.Users)

	if lw.Upstream != "" {
		ob, err := newOutbound(lw.Upstream)
		if err != nil {
			return fmt.Errorf("configure upstream: %w", err)
		}
		lw.dialFunc = ob.DialContext
		lw.listenPacketFunc = ob.ListenPacket
		upstreamURL, _ := url.Parse(lw.Upstream)
		lw.logger.Info("anytls outbound upstream configured",
			zap.String("scheme", upstreamURL.Scheme),
			zap.String("address", upstreamURL.Host),
		)
	}

	service, err := singanytls.NewService(singanytls.ServiceConfig{
		PaddingScheme: []byte(lw.PaddingScheme),
		Users:         lw.anyTLSUsers(),
		Handler:       &directTCPHandler{config: lw},
		Logger:        zapLogger{base: lw.logger},
	})
	if err != nil {
		return fmt.Errorf("create sing-anytls service: %w", err)
	}
	lw.service = service

	return nil
}

// Validate checks static configuration safety.
func (lw *ListenerWrapper) Validate() error {
	if lw.MaxConcurrent < 0 {
		return fmt.Errorf("max_concurrent must be positive")
	}
	if lw.ProbeTimeout < 0 {
		return fmt.Errorf("probe_timeout must be non-negative")
	}
	if lw.IdleTimeout < 0 {
		return fmt.Errorf("idle_timeout must be non-negative")
	}
	if lw.ConnectTimeout < 0 {
		return fmt.Errorf("connect_timeout must be non-negative")
	}

	if lw.Upstream != "" {
		u, err := url.Parse(lw.Upstream)
		if err != nil {
			return fmt.Errorf("parse upstream URL: %w", err)
		}
		switch strings.ToLower(u.Scheme) {
		case "socks", "socks5":
		case "":
			return fmt.Errorf("upstream URL missing scheme")
		default:
			return fmt.Errorf("unsupported upstream scheme %q (supported: socks5)", u.Scheme)
		}
		if u.Host == "" {
			return fmt.Errorf("upstream URL missing host")
		}
	}

	if lw.PassthroughUoT && lw.Upstream == "" {
		return fmt.Errorf("passthrough_uot requires a socks5 upstream to be configured")
	}

	seen := make([]string, 0, len(lw.Users))
	for _, user := range lw.Users {
		if user.Name == "" {
			return fmt.Errorf("user name must not be empty")
		}
		if user.Password == "" {
			return fmt.Errorf("user %q password must not be empty", user.Name)
		}
		if slices.Contains(seen, user.Name) {
			return fmt.Errorf("duplicate user %q", user.Name)
		}
		seen = append(seen, user.Name)
	}

	return nil
}

// WrapListener wraps the listener with AnyTLS-aware connection routing.
func (lw *ListenerWrapper) WrapListener(l net.Listener) net.Listener {
	return &wrappedListener{
		Listener: l,
		config:   lw,
	}
}

// UnmarshalCaddyfile configures the listener wrapper from Caddyfile tokens.
func (lw *ListenerWrapper) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next()
	if d.NextArg() {
		return d.ArgErr()
	}

	for d.NextBlock(0) {
		switch d.Val() {
		case "probe_timeout":
			dur, err := parseDurationDirective(d, "probe_timeout")
			if err != nil {
				return err
			}
			lw.ProbeTimeout = caddy.Duration(dur)

		case "idle_timeout":
			dur, err := parseDurationDirective(d, "idle_timeout")
			if err != nil {
				return err
			}
			lw.IdleTimeout = caddy.Duration(dur)

		case "connect_timeout":
			dur, err := parseDurationDirective(d, "connect_timeout")
			if err != nil {
				return err
			}
			lw.ConnectTimeout = caddy.Duration(dur)

		case "max_concurrent":
			if !d.NextArg() {
				return d.ArgErr()
			}
			value, err := strconv.Atoi(d.Val())
			if err != nil {
				return d.Errf("parsing max_concurrent: %v", err)
			}
			lw.MaxConcurrent = value

		case "fallback":
			value, err := parseBoolDirective(d, "fallback")
			if err != nil {
				return err
			}
			lw.Fallback = &value

		case "allow_private_targets":
			value, err := parseBoolDirective(d, "allow_private_targets")
			if err != nil {
				return err
			}
			lw.AllowPrivateTargets = value

		case "padding_scheme":
			if !d.NextArg() {
				return d.ArgErr()
			}
			lw.PaddingScheme = d.Val()

		case "user":
			args := d.RemainingArgs()
			if len(args) != 2 {
				return d.ArgErr()
			}
			lw.Users = append(lw.Users, User{
				Name:     args[0],
				Password: args[1],
				Enabled:  true,
			})

		case "upstream":
			if !d.NextArg() {
				return d.ArgErr()
			}
			lw.Upstream = d.Val()

		case "passthrough_uot":
			if d.NextArg() {
				return d.ArgErr()
			}
			lw.PassthroughUoT = true

		default:
			return d.ArgErr()
		}
	}

	return nil
}

var (
	_ caddy.Provisioner     = (*ListenerWrapper)(nil)
	_ caddy.Validator       = (*ListenerWrapper)(nil)
	_ caddy.ListenerWrapper = (*ListenerWrapper)(nil)
	_ caddyfile.Unmarshaler = (*ListenerWrapper)(nil)
)

func (lw *ListenerWrapper) fallbackEnabled() bool {
	return lw.Fallback != nil && *lw.Fallback
}

func (lw *ListenerWrapper) anyTLSUsers() []singanytls.User {
	users := make([]singanytls.User, 0, len(lw.Users))
	for _, user := range lw.Users {
		if !user.Enabled {
			continue
		}
		users = append(users, singanytls.User{
			Name:     user.Name,
			Password: user.Password,
		})
	}
	return users
}

type directTCPHandler struct {
	config *ListenerWrapper
}

func (h *directTCPHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	startedAt := time.Now()
	connectionID := connectionIDFromContext(ctx)
	h.config.updateSessionUser(connectionID, userFromContext(ctx))
	closeOnce := N.OnceClose(func(err error) {
		if onClose != nil {
			onClose(err)
		}
	})

	if isUDPOverTCPDestination(destination) {
		if h.config.PassthroughUoT && h.config.dialFunc != nil {
			h.handleUoTPassthrough(ctx, conn, source, destination, startedAt, connectionID, closeOnce)
			return
		}
		h.handleUDPOverTCP(ctx, conn, source, destination, startedAt, connectionID, closeOnce)
		return
	}

	outbound, err := h.dialContext(ctx, destination)
	if err != nil {
		h.logOutboundFailure(connectionID, source, destination, startedAt, userFromContext(ctx), err)
		closeOnce(err)
		_ = conn.Close()
		return
	}

	h.config.logger.Info("anytls connection established",
		zap.Uint64("connection_id", connectionID),
		zap.String("event", "anytls_session"),
		zap.String("outcome", "authenticated"),
		zap.String("protocol", "tcp"),
		zap.String("user", userFromContext(ctx)),
		zap.String("source", source.String()),
		zap.String("destination", destination.String()),
	)

	relay(ctx, conn, outbound, closeOnce)
}

func (h *directTCPHandler) handleUDPOverTCP(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, startedAt time.Time, connectionID uint64, closeOnce N.CloseHandlerFunc) {
	request, err := h.readUDPOverTCPRequest(conn, destination)
	if err != nil {
		h.logOutboundFailure(connectionID, source, destination, startedAt, userFromContext(ctx), err)
		closeOnce(err)
		_ = conn.Close()
		return
	}

	packetConn, err := h.listenPacketContext(ctx)
	if err != nil {
		h.logOutboundFailure(connectionID, source, request.Destination, startedAt, userFromContext(ctx), err)
		closeOnce(err)
		_ = conn.Close()
		return
	}

	uotConn := uot.NewConn(conn, *request)
	h.config.logger.Info("anytls connection established",
		zap.Uint64("connection_id", connectionID),
		zap.String("event", "anytls_session"),
		zap.String("outcome", "authenticated"),
		zap.String("protocol", "udp_over_tcp_v2"),
		zap.Bool("uot_is_connect", request.IsConnect),
		zap.String("user", userFromContext(ctx)),
		zap.String("source", source.String()),
		zap.String("destination", request.Destination.String()),
	)

	// When an upstream is configured the SOCKS5 layer resolves FQDN targets
	// remotely (domain ATYP); resolving them here would leak the DNS query
	// off the landing host and bypass the upstream/audit. The direct path
	// has no such layer, so FQDNs must still be resolved locally there.
	resolveFQDNRemotely := h.config.listenPacketFunc != nil
	relayUDPOverTCP(ctx, uotConn, packetConn, resolveFQDNRemotely, h.validateDestination, closeOnce)
}

func (h *directTCPHandler) dialContext(ctx context.Context, destination M.Socksaddr) (net.Conn, error) {
	if err := h.validateDestination(destination); err != nil {
		return nil, err
	}

	if h.config.dialFunc != nil {
		return h.dialUpstreamTCP(ctx, destination)
	}
	dialer := &net.Dialer{
		Timeout: time.Duration(h.config.ConnectTimeout),
	}
	return dialer.DialContext(ctx, "tcp", destination.String())
}

// dialUpstreamTCP dials destination through the configured upstream over TCP.
// The custom dialer's Timeout is only honored on the direct path, so the
// configured connect_timeout is applied via the context instead. sing's socks
// client uses ctx only during dial setup, so cancelling once the dial returns
// does not affect the conn — callers must therefore pass the original
// (un-timed) context to any subsequent relay, not this bounded child.
func (h *directTCPHandler) dialUpstreamTCP(ctx context.Context, destination M.Socksaddr) (net.Conn, error) {
	ctx, cancel := h.dialTimeoutContext(ctx)
	defer cancel()
	return h.config.dialFunc(ctx, "tcp", destination.String())
}

// handleUoTPassthrough forwards the UoT magic-address CONNECT verbatim to the
// SOCKS5 upstream instead of decoding UDP locally, so a UoT-aware upstream
// (e.g. sing-box) terminates the UoT framing and observes the UDP itself.
// Only reachable when passthrough_uot is set and a SOCKS5 upstream is
// configured. The magic address carries port 0, which validateDestination
// (and the stdlib SOCKS5 dialer) reject — sing's socks client behind dialFunc
// tolerates it, so we dial it directly and deliberately skip
// validateDestination. relay() gets the original ctx, not the dial-bounded
// child, so connect_timeout does not tear down the established tunnel.
func (h *directTCPHandler) handleUoTPassthrough(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, startedAt time.Time, connectionID uint64, closeOnce N.CloseHandlerFunc) {
	outbound, err := h.dialUpstreamTCP(ctx, destination)
	if err != nil {
		h.logOutboundFailure(connectionID, source, destination, startedAt, userFromContext(ctx), err)
		closeOnce(err)
		_ = conn.Close()
		return
	}

	h.config.logger.Info("anytls connection established",
		zap.Uint64("connection_id", connectionID),
		zap.String("event", "anytls_session"),
		zap.String("outcome", "authenticated"),
		zap.String("protocol", "udp_over_tcp_passthrough"),
		zap.String("user", userFromContext(ctx)),
		zap.String("source", source.String()),
		zap.String("destination", destination.String()),
	)

	relay(ctx, conn, outbound, closeOnce)
}

// dialTimeoutContext derives a child context bounded by the configured
// connect_timeout. When the timeout is unset it returns a no-op cancel so
// callers can unconditionally defer cancel().
func (h *directTCPHandler) dialTimeoutContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if h.config.ConnectTimeout > 0 {
		return context.WithTimeout(ctx, time.Duration(h.config.ConnectTimeout))
	}
	return ctx, func() {}
}

func (h *directTCPHandler) listenPacketContext(ctx context.Context) (net.PacketConn, error) {
	if h.config.listenPacketFunc != nil {
		// Same rationale as dialContext: bound the SOCKS5 UDP-ASSOCIATE
		// setup by connect_timeout via the context.
		ctx, cancel := h.dialTimeoutContext(ctx)
		defer cancel()
		return h.config.listenPacketFunc(ctx, "udp", "")
	}

	listenConfig := net.ListenConfig{}
	return listenConfig.ListenPacket(ctx, "udp", "")
}

func (h *directTCPHandler) readUDPOverTCPRequest(conn net.Conn, destination M.Socksaddr) (*uot.Request, error) {
	switch destination.Fqdn {
	case uot.MagicAddress:
		request, err := uot.ReadRequest(conn)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", errInvalidUDPOverTCPRequest, err)
		}
		if request.IsConnect {
			if err := h.validateDestination(request.Destination); err != nil {
				return nil, err
			}
		}
		return request, nil
	case uot.LegacyMagicAddress:
		return &uot.Request{}, nil
	default:
		return nil, fmt.Errorf("%w: %s", errUnsupportedUDPOverTCP, destination.String())
	}
}

func (h *directTCPHandler) validateDestination(destination M.Socksaddr) error {
	if !destination.IsValid() || destination.Port == 0 {
		return fmt.Errorf("%w", errInvalidDestination)
	}
	if !h.config.AllowPrivateTargets && isPrivateDestination(destination) {
		return fmt.Errorf("%w: %s", errPrivateDestinationDenied, destination.String())
	}
	return nil
}

func (h *directTCPHandler) logOutboundFailure(connectionID uint64, source M.Socksaddr, destination M.Socksaddr, startedAt time.Time, user string, err error) {
	protocol := "tcp"
	if isUDPOverTCPDestination(destination) {
		protocol = "udp_over_tcp_v2"
	}
	h.config.logger.Warn("anytls outbound dial failed",
		zap.Uint64("connection_id", connectionID),
		zap.String("event", "anytls_outbound"),
		zap.String("outcome", "rejected"),
		zap.String("reason", dialFailureReason(err)),
		zap.String("protocol", protocol),
		zap.String("user", user),
		zap.String("source", source.String()),
		zap.String("destination", destination.String()),
		zap.Duration("duration", time.Since(startedAt)),
		zap.Error(err),
	)
}

func isUDPOverTCPDestination(destination M.Socksaddr) bool {
	return destination.Fqdn == uot.MagicAddress || destination.Fqdn == uot.LegacyMagicAddress
}

func isPrivateDestination(destination M.Socksaddr) bool {
	if !destination.Addr.IsValid() {
		return false
	}
	addr := destination.Addr.Unmap()
	privateRanges := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("172.16.0.0/12"),
		netip.MustParsePrefix("192.168.0.0/16"),
		netip.MustParsePrefix("127.0.0.0/8"),
		netip.MustParsePrefix("169.254.0.0/16"),
		netip.MustParsePrefix("::1/128"),
		netip.MustParsePrefix("fc00::/7"),
		netip.MustParsePrefix("fe80::/10"),
	}
	for _, prefix := range privateRanges {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func (lw *ListenerWrapper) logFallback(conn net.Conn, err error) {
	lw.logger.Debug("connection routed to website",
		zap.String("remote", conn.RemoteAddr().String()),
		zap.String("event", "fallback"),
		zap.String("outcome", "fallback"),
		zap.String("reason", probeFailureReason(err)),
		zap.Error(err),
	)
}

func (lw *ListenerWrapper) prepareWebsiteConn(conn *bufferedConn) (net.Conn, error) {
	prefix, err := conn.BufferedBytes()
	if err != nil {
		return nil, err
	}

	websiteConn := newPrependConn(conn.Conn, prefix)
	if stater, ok := conn.Conn.(interface{ ConnectionState() tls.ConnectionState }); ok {
		lw.websiteConns.Store(websiteConn, tlsStateConn{
			Conn:  websiteConn,
			state: stater.ConnectionState(),
		})
	}

	return websiteConn, nil
}

func (lw *ListenerWrapper) websiteConnContext(ctx context.Context, conn net.Conn) context.Context {
	shadowConn, ok := lw.websiteConns.Load(conn)
	if !ok {
		return ctx
	}
	return context.WithValue(ctx, caddyhttp.ConnCtxKey, shadowConn)
}

func (lw *ListenerWrapper) cleanupWebsiteConn(conn net.Conn, state http.ConnState) {
	switch state {
	case http.StateClosed, http.StateHijacked:
		lw.websiteConns.Delete(conn)
	}
}

var (
	errInvalidDestination       = errors.New("invalid destination")
	errPrivateDestinationDenied = errors.New("private destination denied")
	errInvalidUDPOverTCPRequest = errors.New("invalid udp over tcp request")
	errUnsupportedUDPOverTCP    = errors.New("unsupported udp over tcp")
)

func (lw *ListenerWrapper) nextConnectionID() uint64 {
	return atomic.AddUint64(&lw.connSeq, 1)
}

func probeFailureReason(err error) string {
	switch {
	case errors.Is(err, errShortPreview):
		return "short_preview"
	case errors.Is(err, errUnknownUserHash):
		return "unknown_user_hash"
	case errors.Is(err, errDisabledUserHash):
		return "disabled_user"
	default:
		return "probe_error"
	}
}

func dialFailureReason(err error) string {
	switch {
	case errors.Is(err, errInvalidDestination):
		return "invalid_destination"
	case errors.Is(err, errPrivateDestinationDenied):
		return "private_target_denied"
	case errors.Is(err, errInvalidUDPOverTCPRequest):
		return "invalid_udp_over_tcp_request"
	case errors.Is(err, errUnsupportedUDPOverTCP):
		return "udp_over_tcp_unsupported"
	default:
		return "dial_failed"
	}
}

func parseDurationDirective(d *caddyfile.Dispenser, name string) (time.Duration, error) {
	if !d.NextArg() {
		return 0, d.ArgErr()
	}
	dur, err := caddy.ParseDuration(d.Val())
	if err != nil {
		return 0, d.Errf("parsing %s duration: %v", name, err)
	}
	return dur, nil
}

func parseBoolDirective(d *caddyfile.Dispenser, name string) (bool, error) {
	if !d.NextArg() {
		return false, d.ArgErr()
	}
	value, err := strconv.ParseBool(d.Val())
	if err != nil {
		return false, d.Errf("parsing %s boolean: %v", name, err)
	}
	return value, nil
}
