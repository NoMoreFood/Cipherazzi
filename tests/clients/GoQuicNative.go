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
	"time"

	"github.com/quic-go/quic-go"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	role, address, certificate, key, mode := os.Args[1], os.Args[2], os.Args[3], os.Args[4], os.Args[5]
	pem, err := os.ReadFile(certificate)
	if err != nil {
		return err
	}
	roots := x509.NewCertPool()
	if mode != "reject" && !roots.AppendCertsFromPEM(pem) {
		return fmt.Errorf("invalid fixture certificate")
	}
	identity, err := tls.LoadX509KeyPair(certificate, key)
	if err != nil {
		return err
	}
	configured := &tls.Config{RootCAs: roots, ServerName: "coverage.test", NextProtos: []string{"coverage"},
		Certificates: []tls.Certificate{identity}, MinVersion: tls.VersionTLS13}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var connection *quic.Conn
	if role == "server" {
		listener, err := quic.ListenAddr(address, configured, nil)
		if err != nil {
			return err
		}
		defer listener.Close()
		fmt.Println(listener.Addr().(*net.UDPAddr).Port)
		connection, err = listener.Accept(ctx)
		if err != nil {
			return err
		}
	} else {
		remote, err := net.ResolveUDPAddr("udp", address)
		if err != nil {
			return err
		}
		local := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}
		if remote.IP.To4() == nil {
			local.IP = net.IPv6loopback
		}
		socket, err := net.ListenUDP("udp", local)
		if err != nil {
			return err
		}
		defer socket.Close()
		connection, err = quic.Dial(ctx, socket, remote, configured, nil)
		if mode == "reject" {
			if err == nil {
				connection.CloseWithError(0, "")
				return fmt.Errorf("untrusted peer was accepted")
			}
			return nil
		}
		if err != nil {
			return err
		}
	}
	defer connection.CloseWithError(0, "")
	var stream *quic.Stream
	if role == "server" {
		stream, err = connection.AcceptStream(ctx)
	} else {
		stream, err = connection.OpenStreamSync(ctx)
	}
	if err != nil {
		return err
	}
	payload := []byte("private-application-payload")
	if role == "client" {
		if _, err = stream.Write(payload); err == nil {
			_, err = io.ReadFull(stream, payload)
		}
	} else {
		if _, err = io.ReadFull(stream, payload); err == nil {
			_, err = stream.Write(payload)
		}
	}
	if err != nil || string(payload) != "private-application-payload" {
		return fmt.Errorf("echo failed: %v", err)
	}
	state := connection.ConnectionState().TLS
	json.NewEncoder(os.Stdout).Encode(map[string]any{"local": connection.LocalAddr().String(),
		"remote": connection.RemoteAddr().String(), "version": state.Version, "cipher": state.CipherSuite,
		"group": state.CurveID})
	if role == "server" {
		<-connection.Context().Done()
	}
	return nil
}
