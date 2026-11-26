package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func InitCA(caCertPath, caKeyPath, org string, validDays int) error {
	if org == "" {
		org = "Relay-Download Internal CA"
	}
	if validDays <= 0 {
		validDays = 3650
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate ca key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return err
	}
	now := time.Now().Add(-5 * time.Minute)
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{org},
			CommonName:   org,
		},
		NotBefore:             now,
		NotAfter:              now.AddDate(0, 0, validDays),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return fmt.Errorf("create ca cert: %w", err)
	}
	if err := writePEM(caCertPath, "CERTIFICATE", der, 0o644); err != nil {
		return err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return fmt.Errorf("marshal ca key: %w", err)
	}
	return writePEM(caKeyPath, "EC PRIVATE KEY", keyDER, 0o600)
}

func IssueCertBytes(caCertPath, caKeyPath, commonName string, ips []string, dnsNames []string, validDays int) ([]byte, []byte, error) {
	if validDays <= 0 {
		validDays = 825
	}
	caCert, caKey, err := loadCA(caCertPath, caKeyPath)
	if err != nil {
		return nil, nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate leaf key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, nil, err
	}
	var parsedIPs []net.IP
	for _, raw := range ips {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		ip := net.ParseIP(raw)
		if ip == nil {
			return nil, nil, fmt.Errorf("invalid IP address: %q", raw)
		}
		parsedIPs = append(parsedIPs, ip)
	}
	var cleanDNS []string
	for _, d := range dnsNames {
		d = strings.TrimSpace(d)
		if d != "" {
			cleanDNS = append(cleanDNS, d)
		}
	}
	if len(parsedIPs) == 0 && len(cleanDNS) == 0 {
		return nil, nil, errors.New("at least one IP or DNS SAN is required")
	}
	if commonName == "" {
		if len(parsedIPs) > 0 {
			commonName = parsedIPs[0].String()
		} else {
			commonName = cleanDNS[0]
		}
	}

	now := time.Now().Add(-5 * time.Minute)
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"Relay-Download Node"},
			CommonName:   commonName,
		},
		NotBefore:             now,
		NotAfter:              now.AddDate(0, 0, validDays),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IPAddresses:           parsedIPs,
		DNSNames:              cleanDNS,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		return nil, nil, fmt.Errorf("create leaf cert: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal leaf key: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, nil
}

func IssueCert(caCertPath, caKeyPath, certOutPath, keyOutPath, commonName string, ips []string, dnsNames []string, validDays int) error {
	certPEM, keyPEM, err := IssueCertBytes(caCertPath, caKeyPath, commonName, ips, dnsNames, validDays)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(certOutPath), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(certOutPath, certPEM, 0o644); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(keyOutPath), 0o755); err != nil {
		return err
	}
	return os.WriteFile(keyOutPath, keyPEM, 0o600)
}

func ServerTLSConfig(certFile, keyFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load tls keypair: %w", err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{"h2", "http/1.1"},
	}, nil
}

func ClientTLSConfig(caCertPath string) (*tls.Config, error) {
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
	}
	if caCertPath != "" {
		pemBytes, err := os.ReadFile(caCertPath)
		if err != nil {
			return nil, fmt.Errorf("read ca cert %s: %w", caCertPath, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pemBytes) {
			return nil, fmt.Errorf("failed to parse ca cert %s", caCertPath)
		}
		cfg.RootCAs = pool
	}
	return cfg, nil
}

func loadCA(certPath, keyPath string) (*x509.Certificate, any, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, nil, fmt.Errorf("read ca cert: %w", err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, nil, errors.New("invalid ca cert pem")
	}
	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse ca cert: %w", err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("read ca key: %w", err)
	}
	kBlock, _ := pem.Decode(keyPEM)
	if kBlock == nil {
		return nil, nil, errors.New("invalid ca key pem")
	}
	caKey, err := x509.ParseECPrivateKey(kBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse ca key: %w", err)
	}
	return caCert, caKey, nil
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	s, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("generate serial: %w", err)
	}
	return s, nil
}

func writePEM(path, typ string, data []byte, perm os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	defer f.Close()
	return pem.Encode(f, &pem.Block{Type: typ, Bytes: data})
}
