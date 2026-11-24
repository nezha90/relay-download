package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"relay-download/internal/center"
	"relay-download/internal/pki"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "serve":
		runServe(os.Args[2:])
	case "pki":
		runPKI(os.Args[2:])
	default:
		// Allow `relay-center -config center.yaml` shorthand.
		if strings.HasPrefix(os.Args[1], "-") {
			runServe(os.Args[1:])
			return
		}
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `Usage:
  relay-center serve -config <center.yaml>
  relay-center pki init-ca -out <dir> [-org <name>] [-days 3650]
  relay-center pki issue -ca <ca.crt> -ca-key <ca.key> -out <dir> -name <node> -ip <ip1,ip2> [-dns <d1,d2>] [-days 825]
`)
}

func runServe(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	cfgPath := fs.String("config", "center.yaml", "path to center yaml config")
	_ = fs.Parse(args)

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	cfg, err := center.LoadConfig(*cfgPath)
	if err != nil {
		logger.Error("load config failed", "err", err)
		os.Exit(1)
	}
	srv, err := center.New(cfg, logger)
	if err != nil {
		logger.Error("init center failed", "err", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := srv.Start(ctx); err != nil {
		logger.Error("center server exited with error", "err", err)
		os.Exit(1)
	}
}

func runPKI(args []string) {
	if len(args) < 1 {
		usage()
		os.Exit(1)
	}
	switch args[0] {
	case "init-ca":
		fs := flag.NewFlagSet("pki init-ca", flag.ExitOnError)
		outDir := fs.String("out", "./certs", "output directory")
		org := fs.String("org", "Relay-Download Internal CA", "CA organization name")
		days := fs.Int("days", 3650, "validity in days")
		_ = fs.Parse(args[1:])

		certPath := filepath.Join(*outDir, "ca.crt")
		keyPath := filepath.Join(*outDir, "ca.key")
		if err := pki.InitCA(certPath, keyPath, *org, *days); err != nil {
			fmt.Fprintf(os.Stderr, "init-ca failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Root CA generated:\n  Cert: %s\n  Key:  %s\n", certPath, keyPath)

	case "issue":
		fs := flag.NewFlagSet("pki issue", flag.ExitOnError)
		caCert := fs.String("ca", "./certs/ca.crt", "path to ca.crt")
		caKey := fs.String("ca-key", "./certs/ca.key", "path to ca.key")
		outDir := fs.String("out", "./certs", "output directory")
		name := fs.String("name", "node", "certificate filename prefix / CN")
		ips := fs.String("ip", "", "comma-separated IPv4/IPv6 SANs")
		dns := fs.String("dns", "", "comma-separated DNS SANs")
		days := fs.Int("days", 825, "validity in days")
		_ = fs.Parse(args[1:])

		var ipList, dnsList []string
		if *ips != "" {
			ipList = strings.Split(*ips, ",")
		}
		if *dns != "" {
			dnsList = strings.Split(*dns, ",")
		}
		certPath := filepath.Join(*outDir, *name+".crt")
		keyPath := filepath.Join(*outDir, *name+".key")
		if err := pki.IssueCert(*caCert, *caKey, certPath, keyPath, *name, ipList, dnsList, *days); err != nil {
			fmt.Fprintf(os.Stderr, "issue cert failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Node certificate generated:\n  Cert: %s\n  Key:  %s\n", certPath, keyPath)

	default:
		usage()
		os.Exit(1)
	}
}
