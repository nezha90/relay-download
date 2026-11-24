package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"relay-download/internal/agenta"
	"relay-download/internal/version"
)

func main() {
	cfgPath := flag.String("config", "agent-a.yaml", "path to agent-a yaml config")
	showVer := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVer {
		fmt.Println(version.String("relay-agent-a"))
		return
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	cfg, err := agenta.LoadConfig(*cfgPath)
	if err != nil {
		logger.Error("load agent-a config failed", "err", err)
		os.Exit(1)
	}

	ag, err := agenta.New(cfg, logger)
	if err != nil {
		logger.Error("init agent-a failed", "err", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := ag.Start(ctx); err != nil {
		logger.Error("agent-a exited with error", "err", err)
		os.Exit(1)
	}
}
