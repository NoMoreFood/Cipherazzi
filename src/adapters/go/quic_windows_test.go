package endpoint

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

func TestQUICHandshakeCancellationAndReporting(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certificate := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"coverage.test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(parsed)
	directory := t.TempDir()
	reporter, err := NewReporter(directory)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := quic.ListenAddrEarly("127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		NextProtos:   []string{"coverage"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	socket, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer socket.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	verified, release := make(chan struct{}), make(chan struct{})
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	type outcome struct {
		connection            *quic.Conn
		tlsError, reportError error
	}
	completed := make(chan outcome, 1)
	started := time.Now()
	go func() {
		connection, tlsError, reportError := reporter.DialQUIC(ctx, socket, listener.Addr(), &tls.Config{
			RootCAs: roots, ServerName: "coverage.test", NextProtos: []string{"coverage"},
			VerifyConnection: func(tls.ConnectionState) error {
				close(verified)
				select {
				case <-release:
					return nil
				case <-ctx.Done():
					return ctx.Err()
				}
			}}, nil)
		completed <- outcome{connection, tlsError, reportError}
	}()
	server, err := listener.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer server.CloseWithError(0, "")
	select {
	case <-verified:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	stopped, stop := context.WithCancel(ctx)
	stop()
	tlsError, reportError := reporter.WaitQUIC(stopped, server, "server", started)
	if tlsError != context.Canceled || reportError != nil {
		t.Fatalf("canceled observer changed an ongoing handshake: %v, %v", tlsError, reportError)
	}
	files, _ := filepath.Glob(filepath.Join(directory, "*.json"))
	if len(files) != 0 {
		t.Fatal("canceled observation produced a TLS failure")
	}
	close(release)
	client := <-completed
	if client.tlsError != nil || client.reportError != nil {
		t.Fatalf("client handshake: %v, report: %v", client.tlsError, client.reportError)
	}
	defer client.connection.CloseWithError(0, "")
	tlsError, reportError = reporter.WaitQUIC(ctx, server, "server", started)
	if tlsError != nil || reportError != nil {
		t.Fatalf("server handshake: %v, report: %v", tlsError, reportError)
	}
	tlsError, reportError = reporter.WaitQUIC(stopped, server, "server", started)
	if tlsError != nil || reportError != nil {
		t.Fatalf("completed handshake lost a cancellation race: %v, %v", tlsError, reportError)
	}
	if err := reporter.ObserveQUIC(client.connection, "client"); err != nil {
		t.Fatal(err)
	}
	files, _ = filepath.Glob(filepath.Join(directory, "*.json"))
	if len(files) != 4 {
		t.Fatalf("expected four public reports, got %d", len(files))
	}
	for _, path := range files {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var report map[string]any
		if err := json.Unmarshal(data, &report); err != nil {
			t.Fatal(err)
		}
		if report["success"] != true || report["transport"] != "QUIC" || report["tls_version"] != float64(772) ||
			report["local"] == nil || report["remote"] == nil || report["selected_alpn"] != "coverage" {
			t.Fatalf("invalid public QUIC report: %v", report)
		}
	}
	missing := filepath.Join(t.TempDir(), "removed")
	if err := os.Mkdir(missing, 0700); err != nil {
		t.Fatal(err)
	}
	unavailable, err := NewReporter(missing)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(missing); err != nil {
		t.Fatal(err)
	}
	tlsError, reportError = unavailable.WaitQUIC(ctx, client.connection, "client", started)
	if tlsError != nil || reportError == nil {
		t.Fatalf("report failure changed the successful handshake: %v, %v", tlsError, reportError)
	}
}
