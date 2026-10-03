package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"strconv"
	"sync"
	"time"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	address, certificate, mode := os.Args[1], os.Args[2], os.Args[3]
	count, err := strconv.Atoi(os.Args[4])
	if err != nil || count < 1 || count > 256 {
		return fmt.Errorf("invalid concurrency")
	}
	pem, err := os.ReadFile(certificate)
	if err != nil {
		return err
	}
	roots := x509.NewCertPool()
	if mode != "reject" && !roots.AppendCertsFromPEM(pem) {
		return fmt.Errorf("invalid fixture certificate")
	}
	version := uint16(tls.VersionTLS13)
	if os.Args[5] == "TLSv1.2" {
		version = tls.VersionTLS12
	}
	configured := &tls.Config{RootCAs: roots, ServerName: "coverage.test", NextProtos: []string{"h2"},
		MinVersion: version, MaxVersion: version}
	var workers sync.WaitGroup
	errors := make(chan error, count)
	var output sync.Mutex
	for range count {
		workers.Go(func() {
			raw, err := net.DialTimeout("tcp", address, 10*time.Second)
			if err != nil {
				errors <- err
				return
			}
			defer raw.Close()
			raw.SetDeadline(time.Now().Add(15 * time.Second))
			connection := tls.Client(raw, configured)
			defer connection.Close()
			tlsError := connection.HandshakeContext(context.Background())
			if (tlsError == nil) != (mode != "reject") {
				errors <- fmt.Errorf("unexpected TLS result: %v", tlsError)
				return
			}
			if tlsError == nil {
				payload := []byte("private-application-payload")
				if _, err = connection.Write(payload); err == nil {
					_, err = io.ReadFull(connection, payload)
				}
				if err != nil || string(payload) != "private-application-payload" {
					errors <- fmt.Errorf("echo failed: %v", err)
					return
				}
			}
			state := connection.ConnectionState()
			output.Lock()
			json.NewEncoder(os.Stdout).Encode(map[string]any{"local": raw.LocalAddr().String(),
				"success": tlsError == nil, "version": state.Version, "cipher": state.CipherSuite,
				"group": state.CurveID})
			output.Unlock()
		})
	}
	done := make(chan struct{})
	go func() {
		for {
			select {
			case <-done:
				return
			case <-time.After(time.Millisecond):
				runtime.GC()
			}
		}
	}()
	workers.Wait()
	close(done)
	close(errors)
	for err := range errors {
		return err
	}
	return nil
}
