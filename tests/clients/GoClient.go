package main

import (
	"cipherazzi/endpoint"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"os"
	"time"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	role, version, address, directory, certPath, keyPath, mode :=
		os.Args[1], os.Args[2], os.Args[3], os.Args[4], os.Args[5], os.Args[6], os.Args[7]
	reporter, err := endpoint.NewReporter(directory)
	if err != nil {
		return err
	}
	if mode == "lost-directory" {
		if err = os.Remove(directory); err != nil {
			return err
		}
	}
	certificate, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return err
	}
	pem, err := os.ReadFile(certPath)
	if err != nil {
		return err
	}
	roots := x509.NewCertPool()
	if mode != "reject" && !roots.AppendCertsFromPEM(pem) {
		return fmt.Errorf("invalid fixture certificate")
	}
	wire := uint16(tls.VersionTLS13)
	if version == "TLSv1.2" {
		wire = tls.VersionTLS12
	}
	configured := &tls.Config{MinVersion: wire, MaxVersion: wire, RootCAs: roots, ClientCAs: roots,
		Certificates: []tls.Certificate{certificate}, ServerName: "coverage.test", NextProtos: []string{"h2"},
		ClientSessionCache: tls.NewLRUClientSessionCache(4)}
	var listener net.Listener
	if role == "server" {
		configured.ClientAuth = tls.RequireAndVerifyClientCert
		listener, err = net.Listen("tcp", address)
		if err != nil {
			return err
		}
		defer listener.Close()
		fmt.Println(listener.Addr().(*net.TCPAddr).Port)
	}
	count := 2
	if mode != "ok" {
		count = 1
	}
	for range count {
		var raw net.Conn
		if role == "client" {
			raw, err = net.DialTimeout("tcp", address, 10*time.Second)
		} else {
			raw, err = listener.Accept()
		}
		if err != nil {
			return err
		}
		raw.SetDeadline(time.Now().Add(15 * time.Second))
		var conn *tls.Conn
		if role == "client" {
			conn = tls.Client(raw, configured)
		} else {
			conn = tls.Server(raw, configured)
		}
		tlsErr, reportErr := reporter.Handshake(context.Background(), conn, role)
		if mode == "lost-directory" {
			if reportErr == nil {
				return fmt.Errorf("missing report directory was ignored")
			}
		} else if reportErr != nil {
			return reportErr
		}
		if mode == "reject" {
			conn.Close()
			if tlsErr == nil {
				return fmt.Errorf("untrusted peer was accepted")
			}
			return nil
		}
		if tlsErr != nil {
			return tlsErr
		}
		if mode == "ok" {
			if err = reporter.Observe(conn, role); err != nil {
				return err
			}
		}
		payload := []byte{'*'}
		if role == "client" {
			if _, err = conn.Write(payload); err != nil {
				return err
			}
			if _, err = io.ReadFull(conn, payload); err != nil {
				return err
			}
		} else {
			if _, err = io.ReadFull(conn, payload); err != nil {
				return err
			}
			if _, err = conn.Write(payload); err != nil {
				return err
			}
		}
		conn.Close()
		if payload[0] != '*' {
			return fmt.Errorf("echo did not round trip")
		}
	}
	return nil
}
