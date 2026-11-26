package agentb

import (
	"log/slog"
	"path/filepath"
	"slices"
	"testing"

	"relay-download/internal/protocol"
	"relay-download/internal/transfer"
)

func TestSingleProjectOnlyConfigAndShorthandDirs(t *testing.T) {
	// 1. only_project + dest_dir shorthand
	cfg1 := Config{
		NodeID:      "rx-1",
		CenterURL:   "https://127.0.0.1:8440",
		CenterToken: "tok",
		OnlyProject: "proj-only",
		DestDir:     "/mnt/sda/proj-only",
	}
	cfg1.ApplyDefaults()
	if err := cfg1.Validate(); err != nil {
		t.Fatalf("cfg1 validate: %v", err)
	}
	if !slices.Equal(cfg1.ProjectIDs(), []string{"proj-only"}) {
		t.Fatalf("unexpected cfg1 ProjectIDs: %v", cfg1.ProjectIDs())
	}
	if !slices.Equal(cfg1.DestDirsFor("proj-only"), []string{"/mnt/sda/proj-only"}) {
		t.Fatalf("unexpected cfg1 DestDirsFor: %v", cfg1.DestDirsFor("proj-only"))
	}
	if dirs := cfg1.DestDirsFor("other-proj"); len(dirs) != 0 {
		t.Fatalf("expected nil dirs for excluded project, got %v", dirs)
	}

	// 2. only_project overrides multi-project map (strictly filters out other projects)
	cfg2 := Config{
		NodeID:      "rx-2",
		CenterURL:   "https://127.0.0.1:8440",
		CenterToken: "tok",
		OnlyProject: "proj-a",
		Projects: map[string]string{
			"proj-a": "/data/a",
			"proj-b": "/data/b",
		},
		DestDirs: []string{"/data/a-2", "/data/a"},
	}
	cfg2.ApplyDefaults()
	if err := cfg2.Validate(); err != nil {
		t.Fatalf("cfg2 validate: %v", err)
	}
	if !slices.Equal(cfg2.ProjectIDs(), []string{"proj-a"}) {
		t.Fatalf("expected only [proj-a], got %v", cfg2.ProjectIDs())
	}
	if !slices.Equal(cfg2.DestDirsFor("proj-a"), []string{"/data/a", "/data/a-2"}) {
		t.Fatalf("unexpected cfg2 DestDirsFor(proj-a): %v", cfg2.DestDirsFor("proj-a"))
	}
	if dirs := cfg2.DestDirsFor("proj-b"); len(dirs) != 0 {
		t.Fatalf("expected proj-b to be strictly blocked by only_project, got %v", dirs)
	}

	// 3. only_project without any destination dir must fail validation
	cfg3 := Config{
		NodeID:      "rx-3",
		CenterURL:   "https://127.0.0.1:8440",
		CenterToken: "tok",
		OnlyProject: "proj-missing",
		Projects:    map[string]string{"proj-other": "/data/other"},
	}
	cfg3.ApplyDefaults()
	if err := cfg3.Validate(); err == nil {
		t.Fatalf("expected validation error when only_project has no mapped dest dir")
	}
}

func TestStorageDirsPoolDirectiveAndDiskPolicies(t *testing.T) {
	root1 := filepath.Join(t.TempDir(), "disk1")
	root2 := filepath.Join(t.TempDir(), "disk2")

	cfg := Config{
		NodeID:      "rx-pool",
		CenterURL:   "https://127.0.0.1:8440",
		CenterToken: "tok",
		StorageDirs: []string{root1, root2},
	}
	cfg.ApplyDefaults()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("storage_dirs-only config should validate: %v", err)
	}
	if !slices.Equal(cfg.DiskRoots(), []string{root1, root2}) {
		t.Fatalf("unexpected DiskRoots: %v", cfg.DiskRoots())
	}

	// Dynamic <storage_dir>/<project_id> resolution + traversal guard.
	gotDirs := cfg.DestDirsFor("proj-new")
	wantDirs := []string{filepath.Join(root1, "proj-new"), filepath.Join(root2, "proj-new")}
	if !slices.Equal(gotDirs, wantDirs) {
		t.Fatalf("unexpected DestDirsFor(proj-new): got %v want %v", gotDirs, wantDirs)
	}
	if bad := cfg.DestDirsFor("../escape"); len(bad) != 0 {
		t.Fatalf("expected traversal project id to be rejected, got %v", bad)
	}

	ag := &Agent{
		cfg:             &cfg,
		logger:          slog.Default(),
		discCache:       make(map[string]cachedDiscover),
		wakeupCh:        make(chan string, 16),
		projectSchedule: cfg.ProjectSchedule,
		diskPolicy:      cfg.DiskPolicy,
		diskHealth:      transfer.NewDiskHealthTracker(),
	}

	// 1. Center directive in "all" mode populates activeProjectIDs in exact KnownProjects (FIFO) order.
	ag.applyDirective(&protocol.ReceiverDirective{
		ProjectMode:     "all",
		KnownProjects:   []string{"proj-1", "proj-2", "proj-3"},
		ProjectSchedule: protocol.ScheduleFIFO,
		DiskPolicy:      protocol.DiskPolicyRoundRobin,
	}, nil)
	if !slices.Equal(ag.activeProjectIDs(), []string{"proj-1", "proj-2", "proj-3"}) {
		t.Fatalf("expected FIFO order [proj-1 proj-2 proj-3], got %v", ag.activeProjectIDs())
	}
	if ag.sseProjectsQuery() != "*" {
		t.Fatalf("expected wildcard SSE query in storage_dirs+all mode, got %q", ag.sseProjectsQuery())
	}

	// Round-robin disk selection alternates between disk1 and disk2.
	pA := ag.chooseDestDir("proj-1", "a.m4a", 1024)
	pB := ag.chooseDestDir("proj-1", "b.m4a", 1024)
	if pA == pB {
		t.Fatalf("expected round_robin to alternate disks, got %q twice", pA)
	}

	// 2. Center dynamically switches to single project "proj-2" + disables disk1 + sets "first" disk policy.
	ag.applyDirective(&protocol.ReceiverDirective{
		ProjectMode:     "selected",
		AllowedProjects: []string{"proj-2"},
		KnownProjects:   []string{"proj-1", "proj-2", "proj-3"},
		ProjectSchedule: protocol.ScheduleFair,
		DiskPolicy:      protocol.DiskPolicyFirst,
		DisabledDisks:   []string{root1},
	}, []string{"proj-2"})

	if !slices.Equal(ag.activeProjectIDs(), []string{"proj-2"}) {
		t.Fatalf("expected single selected [proj-2], got %v", ag.activeProjectIDs())
	}
	if ag.isProjectAllowed("proj-1") {
		t.Fatalf("proj-1 should be disallowed after directive switch")
	}
	if ag.sseProjectsQuery() != "proj-2" {
		t.Fatalf("expected SSE query 'proj-2', got %q", ag.sseProjectsQuery())
	}
	enabledDirs := ag.enabledDestDirsFor("proj-2")
	if !slices.Equal(enabledDirs, []string{filepath.Join(root2, "proj-2")}) {
		t.Fatalf("expected only disk2 enabled after disabling root1, got %v", enabledDirs)
	}
	if chosen := ag.chooseDestDir("proj-2", "clip.opus", 1024); chosen != filepath.Join(root2, "proj-2") {
		t.Fatalf("expected disabled disk1 to be skipped, got %q", chosen)
	}
}
