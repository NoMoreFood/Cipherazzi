package endpoint

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"time"

	"github.com/quic-go/quic-go"
)

// DialQUIC waits for authentication before reporting success, including when 0-RTT is available.
// TLS and report errors are separate. The caller owns the packet socket and returned connection.
func (r *Reporter) DialQUIC(ctx context.Context, socket net.PacketConn, remote net.Addr,
	configuration *tls.Config, options *quic.Config) (connection *quic.Conn, tlsError, reportError error) {
	started := time.Now()
	connection, tlsError = quic.DialEarly(ctx, socket, remote, configuration, options)
	if tlsError == nil {
		tlsError, reportError = r.WaitQUIC(ctx, connection, "client", started)
		return
	}
	state := tls.ConnectionState{ServerName: configuration.ServerName}
	reportError = r.writeState(state, socket.LocalAddr(), remote, "QUIC", "client",
		started.UnixMicro(), time.Now().UnixMicro(), false, tlsError)
	return
}

// WaitQUIC reports an early connection after its handshake completes or fails.
// Started must be the application's recorded handshake start, before dialing or accepting this connection.
// Canceling the wait leaves ownership and closure of the connection with the caller.
func (r *Reporter) WaitQUIC(ctx context.Context, connection *quic.Conn, role string,
	started time.Time) (tlsError, reportError error) {
	select {
	case <-connection.HandshakeComplete():
	case <-connection.Context().Done():
		tlsError = context.Cause(connection.Context())
	case <-ctx.Done():
		// Canceling observation does not establish a TLS failure while the connection is still active.
		if !connection.ConnectionState().TLS.HandshakeComplete && connection.Context().Err() == nil {
			return ctx.Err(), nil
		}
	}
	state := connection.ConnectionState().TLS
	if state.HandshakeComplete {
		tlsError = nil
	} else {
		tlsError = context.Cause(connection.Context())
		if tlsError == nil {
			tlsError = errors.New("QUIC handshake did not complete")
		}
	}
	reportError = r.writeState(state, connection.LocalAddr(), connection.RemoteAddr(), "QUIC", role,
		started.UnixMicro(), time.Now().UnixMicro(), false, tlsError)
	return
}

// ObserveQUIC reports a completed QUIC connection without asserting handshake timing.
func (r *Reporter) ObserveQUIC(connection *quic.Conn, role string) error {
	state := connection.ConnectionState().TLS
	if !state.HandshakeComplete {
		return errors.New("QUIC connection is not established")
	}
	return r.writeState(state, connection.LocalAddr(), connection.RemoteAddr(), "QUIC", role,
		0, time.Now().UnixMicro(), true, nil)
}
