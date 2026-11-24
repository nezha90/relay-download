package pki

import (
	"crypto/tls"
	"net"
	"path/filepath"
	"testing"
)

func TestInitCAAndIssueIPCert(t *testing.T) {
	dir := t.TempDir()
	caCert := filepath.Join(dir, "ca.crt")
	caKey := filepath.Join(dir, "ca.key")
	if err := InitCA(caCert, caKey, "Unit Test CA", 30); err != nil {
		t.Fatalf("InitCA: %v", err)
	}
	srvCert := filepath.Join(dir, "srv.crt")
	srvKey := filepath.Join(dir, "srv.key")
	if err := IssueCert(caCert, caKey, srvCert, srvKey, "node-a1", []string{"127.0.0.1"}, nil, 30); err != nil {
		t.Fatalf("IssueCert: %v", err)
	}

	sTLS, err := ServerTLSConfig(srvCert, srvKey)
	if err != nil {
		t.Fatalf("ServerTLSConfig: %v", err)
	}
	cTLS, err := ClientTLSConfig(caCert)
	if err != nil {
		t.Fatalf("ClientTLSConfig: %v", err)
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", sTLS)
	if err != nil {
		t.Fatalf("tls.Listen: %v", err)
	}
	defer ln.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.(*tls.Conn).Handshake()
	}()

	host, _, _ := net.SplitHostPort(ln.Addr().String())
	cTLS.ServerName = host
	conn, err := tls.Dial("tcp", ln.Addr().String(), cTLS)
	if err != nil {
		t.Fatalf("tls.Dial with IP SAN failed: %v", err)
	}
	if conn.ConnectionState().Version != tls.VersionTLS13 {
		t.Fatalf("expected TLS 1.3, got 0x%x", conn.ConnectionState().Version)
	}
	_ = conn.Close()
	<-done

	// Verify TLS 1.2 client downgrade is strictly rejected.
	done12 := make(chan struct{})
	go func() {
		defer close(done12)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.(*tls.Conn).Handshake()
	}()
	tls12Client := cTLS.Clone()
	tls12Client.MinVersion = tls.VersionTLS12
	tls12Client.MaxVersion = tls.VersionTLS12
	if c12, err := tls.Dial("tcp", ln.Addr().String(), tls12Client); err == nil {
		_ = c12.Close()
		t.Fatalf("expected TLS 1.2 handshake to be rejected, but succeeded")
	}
	<-done12
}
