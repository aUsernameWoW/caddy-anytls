package anytls

import (
	"net"
	"time"
)

// idleTimeoutConn resets the read/write deadline before each I/O so the
// underlying timeout fires only after a true period of inactivity. Without
// this, SetDeadline used once at session start would terminate healthy
// long-lived sessions kept alive by AnyTLS v2 heartbeats.
type idleTimeoutConn struct {
	net.Conn
	timeout time.Duration
}

func newIdleTimeoutConn(conn net.Conn, timeout time.Duration) net.Conn {
	if timeout <= 0 {
		return conn
	}
	return &idleTimeoutConn{Conn: conn, timeout: timeout}
}

func (c *idleTimeoutConn) Read(p []byte) (int, error) {
	_ = c.Conn.SetReadDeadline(time.Now().Add(c.timeout))
	return c.Conn.Read(p)
}

func (c *idleTimeoutConn) Write(p []byte) (int, error) {
	_ = c.Conn.SetWriteDeadline(time.Now().Add(c.timeout))
	return c.Conn.Write(p)
}
