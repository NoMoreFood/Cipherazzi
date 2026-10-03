// Package endpoint reports public crypto/tls metadata to a Cipherazzi endpoint directory.
package endpoint

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"
)

// Reporter publishes complete reports atomically. The caller manages directory retention.
type Reporter struct {
	directory string
	started   int64
	path      string
}

// NewReporter uses the current Windows process lifetime and an existing report directory.
func NewReporter(directory string) (*Reporter, error) {
	info, err := os.Stat(directory)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, errors.New("endpoint output is not a directory")
	}
	process, err := syscall.GetCurrentProcess()
	if err != nil {
		return nil, err
	}
	var created, exited, kernel, user syscall.Filetime
	if err = syscall.GetProcessTimes(process, &created, &exited, &kernel, &user); err != nil {
		return nil, err
	}
	path, err := os.Executable()
	if err != nil {
		return nil, err
	}
	return &Reporter{directory, created.Nanoseconds() / 1000, path}, nil
}

// Handshake runs the normal TLS handshake and reports its public outcome.
// TLS and reporting errors are separate; a reporting failure does not change the TLS result.
// Role must identify how the application created conn: "client" or "server".
func (r *Reporter) Handshake(ctx context.Context, conn *tls.Conn, role string) (tlsError, reportError error) {
	alreadyComplete := conn.ConnectionState().HandshakeComplete
	started := time.Now().UnixMicro()
	tlsError = conn.HandshakeContext(ctx)
	reportError = r.write(conn, role, started, time.Now().UnixMicro(), alreadyComplete, tlsError)
	return
}

// Observe reports an established connection without claiming its handshake timing.
func (r *Reporter) Observe(conn *tls.Conn, role string) error {
	if !conn.ConnectionState().HandshakeComplete {
		return errors.New("TLS connection is not established")
	}
	return r.write(conn, role, 0, time.Now().UnixMicro(), true, nil)
}

func (r *Reporter) write(conn *tls.Conn, role string, started, timestamp int64,
	observation bool, tlsError error) error {
	return r.writeState(conn.ConnectionState(), conn.LocalAddr(), conn.RemoteAddr(), "TCP", role,
		started, timestamp, observation, tlsError)
}

func (r *Reporter) writeState(state tls.ConnectionState, local, remote net.Addr, transport, role string,
	started, timestamp int64, observation bool, tlsError error) error {
	if role != "client" && role != "server" {
		return errors.New("invalid TLS role")
	}
	if timestamp < r.started || (!observation && (started < r.started || timestamp < started ||
		timestamp-started > 120_000_000)) {
		return errors.New("endpoint timing is outside the report bounds")
	}
	success := tlsError == nil && state.HandshakeComplete
	report := map[string]any{
		"schema": "cipherazzi.endpoint/1", "provider": "Go/crypto/tls", "pid": os.Getpid(),
		"process_started_us": r.started, "process_name": filepath.Base(r.path), "process_path": r.path,
		"timestamp_us": timestamp, "role": role, "transport": transport, "success": success,
	}
	if observation {
		report["observation"] = "connection"
	} else {
		report["handshake_started_us"] = started
	}
	endpoint := func(address net.Addr) map[string]any {
		var ip net.IP
		var port int
		switch value := address.(type) {
		case *net.TCPAddr:
			if transport != "TCP" {
				return nil
			}
			ip, port = value.IP, value.Port
		case *net.UDPAddr:
			if transport != "QUIC" {
				return nil
			}
			ip, port = value.IP, value.Port
		}
		if ip == nil || ip.IsUnspecified() || port < 1 || port > 65535 {
			return nil
		}
		return map[string]any{"address": ip.String(), "port": port}
	}
	if local, remote := endpoint(local), endpoint(remote); local != nil && remote != nil {
		report["local"], report["remote"] = local, remote
	} else if transport == "TCP" {
		report["transport"] = "Unknown"
	}
	if !success {
		report["error_name"] = "TLS_HANDSHAKE_FAILED"
		var verification *tls.CertificateVerificationError
		if errors.As(tlsError, &verification) {
			report["peer_verified"] = false
			if len(state.PeerCertificates) == 0 {
				state.PeerCertificates = verification.UnverifiedCertificates
			}
		}
	}
	if state.Version != 0 {
		report["tls_version"] = state.Version
	}
	if state.CipherSuite != 0 {
		report["cipher_id"] = state.CipherSuite
	}
	if state.CurveID != 0 {
		report["group_id"] = state.CurveID
	}
	if len(state.ServerName) <= 253 && !strings.ContainsFunc(state.ServerName, func(r rune) bool {
		return r <= 32 || r == 127
	}) {
		report["server_name"] = state.ServerName
	}
	if utf8.ValidString(state.NegotiatedProtocol) {
		report["selected_alpn"] = state.NegotiatedProtocol
	}
	if success {
		report["session_resumed"] = state.DidResume
	}
	if success && len(state.VerifiedChains) > 0 {
		report["peer_verified"] = true
	}
	chain := make([]string, 0)
	bytes := 0
	for _, certificate := range state.PeerCertificates {
		bytes += len(certificate.Raw)
		if len(chain) == 16 || len(certificate.Raw) > 262_144 || bytes > 1_048_576 {
			return errors.New("public certificate chain exceeds the report bounds")
		}
		chain = append(chain, base64.StdEncoding.EncodeToString(certificate.Raw))
	}
	if role == "client" {
		report["server_certificates_der"] = chain
	} else {
		report["client_certificates_der"] = chain
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		return err
	}
	file, err := os.CreateTemp(r.directory, "cipherazzi-go-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	_, writeError := file.Write(encoded)
	closeError := file.Close()
	if writeError != nil || closeError != nil {
		return errors.Join(writeError, closeError)
	}
	return os.Rename(file.Name(), file.Name()+".json")
}
