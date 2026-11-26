package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"relay-download/internal/agentb"
	"relay-download/internal/version"
)

func main() {
	cfgPath := flag.String("config", "agent-b.yaml", "path to agent-b yaml config")
	onlyProj := flag.String("project", "", "optional: restrict this receiver node to download only the specified project ID")
	showVer := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVer {
		fmt.Println(version.String("relay-agent-b"))
		return
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	cfg, err := agentb.LoadConfig(*cfgPath)
	if err != nil {
		logger.Error("load agent-b config failed", "err", err)
		os.Exit(1)
	}
	if *onlyProj != "" {
		cfg.OnlyProject = *onlyProj
		cfg.ApplyDefaults()
		if err := cfg.Validate(); err != nil {
			logger.Error("apply -project override failed", "project", *onlyProj, "err", err)
			os.Exit(1)
		}
		logger.Info("single-project mode enabled via CLI flag", "only_project", cfg.OnlyProject)
	}

	ag, err := agentb.New(cfg, logger)
	if err != nil {
		logger.Error("init agent-b failed", "err", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := ag.Start(ctx); err != nil {
		logger.Error("agent-b exited with error", "err", err)
		os.Exit(1)
	}
}
