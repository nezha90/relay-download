package agentb

import (
	"fmt"
	"log/slog"
	"os"
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
		maxDiskUsagePct: 99.0,
		diskHealth:      transfer.NewDiskHealthTracker(),
	}

	// 1. Center directive in "all" mode populates activeProjectIDs in exact KnownProjects (FIFO) order.
	ag.applyDirective(&protocol.ReceiverDirective{
		ProjectMode:     "all",
		KnownProjects:   []string{"proj-1", "proj-2", "proj-3"},
		ProjectSchedule: protocol.ScheduleFIFO,
		DiskPolicy:      protocol.DiskPolicyRoundRobin,
		MaxDiskUsagePct: 99.0,
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

func TestRollingWindowSlidingDiskSelection(t *testing.T) {
	base := t.TempDir()
	roots := make([]string, 12)
	for i := range roots {
		roots[i] = filepath.Join(base, fmt.Sprintf("disk%d", i+1))
		if err := os.MkdirAll(roots[i], 0o755); err != nil {
			t.Fatalf("mkdir disk%d: %v", i+1, err)
		}
	}

	cfg := Config{
		NodeID:           "rx-100disk",
		CenterURL:        "https://127.0.0.1:8440",
		CenterToken:      "tok",
		StorageDirs:      roots,
		DiskPolicy:       protocol.DiskPolicyRollingWindow,
		ActiveDiskWindow: 3,
	}
	cfg.ApplyDefaults()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("rolling_window config should validate: %v", err)
	}

	ag := &Agent{
		cfg:              &cfg,
		logger:           slog.Default(),
		discCache:        make(map[string]cachedDiscover),
		wakeupCh:         make(chan string, 16),
		projectSchedule:  cfg.ProjectSchedule,
		diskPolicy:       cfg.DiskPolicy,
		activeDiskWindow: cfg.ActiveDiskWindow,
		diskHealth:       transfer.NewDiskHealthTracker(),
	}
	// Verify default receiver watermark is 85% before raising to 99% so tests pass even on full dev laptops.
	if got := ag.effectiveMaxDiskUsagePct(); got != 85.0 {
		t.Fatalf("expected default receiver watermark 85%%, got %.1f", got)
	}
	ag.maxDiskUsagePct = 99.0

	// 1. With active_disk_window=3 across 12 disks, ALL writes must stay strictly within disks 1..3
	//    and paired media+metadata with the same stem must land on the exact same disk.
	seenPhase1 := make(map[string]int)
	for i := 0; i < 60; i++ {
		d := ag.chooseDestDir("proj-tw", fmt.Sprintf("vid_%03d.opus", i), 1024)
		seenPhase1[d]++
		dMeta := ag.chooseDestDir("proj-tw", fmt.Sprintf("vid_%03d.info.json", i), 256)
		if d != dMeta {
			t.Fatalf("paired files must share same disk inside rolling window: %s vs %s", d, dMeta)
		}
	}
	for i := 3; i < 12; i++ {
		if seenPhase1[filepath.Join(roots[i], "proj-tw")] > 0 {
			t.Fatalf("standby disk%d must NOT receive writes while disks 1..3 are healthy", i+1)
		}
	}
	if len(seenPhase1) != 3 {
		t.Fatalf("expected all 3 disks in initial active window to receive writes, got %d: %v", len(seenPhase1), seenPhase1)
	}

	// 2. When disk1 fills up / is disabled (e.g. preparing to eject), disk4 MUST automatically slide
	//    into the 3-disk active window (disks 2, 3, 4), while disks 5..12 stay standby!
	ag.applyDirective(&protocol.ReceiverDirective{
		ProjectMode:      "selected",
		AllowedProjects:  []string{"proj-tw"},
		DiskPolicy:       protocol.DiskPolicyRollingWindow,
		ActiveDiskWindow: 3,
		StorageDirs:      roots,
		DisabledDisks:    []string{roots[0]},
		DiskGen:          1,
		MaxDiskUsagePct:  99.0,
	}, nil)

	seenPhase2 := make(map[string]int)
	for i := 0; i < 60; i++ {
		d := ag.chooseDestDir("proj-tw", fmt.Sprintf("batch2_%03d.opus", i), 1024)
		seenPhase2[d]++
	}
	if seenPhase2[filepath.Join(roots[0], "proj-tw")] > 0 {
		t.Fatalf("disabled disk1 must not receive writes")
	}
	if seenPhase2[filepath.Join(roots[3], "proj-tw")] == 0 {
		t.Fatalf("expected disk4 to slide into active window automatically after disk1 disabled, got %v", seenPhase2)
	}
	for i := 4; i < 12; i++ {
		if seenPhase2[filepath.Join(roots[i], "proj-tw")] > 0 {
			t.Fatalf("standby disk%d must remain idle until earlier disks fill/disable", i+1)
		}
	}

	// 3. Hot-updating MaxDiskUsagePct via ReceiverDirective (1..99%, default 85%) works without restart.
	ag.applyDirective(&protocol.ReceiverDirective{
		ProjectMode:      "selected",
		AllowedProjects:  []string{"proj-tw"},
		DiskPolicy:       protocol.DiskPolicyRollingWindow,
		ActiveDiskWindow: 3,
		StorageDirs:      roots,
		MaxDiskUsagePct:  85.0,
	}, nil)
	if got := ag.effectiveMaxDiskUsagePct(); got != 85.0 {
		t.Fatalf("expected hot-updated receiver watermark 85%%, got %.1f", got)
	}
	ag.applyDirective(&protocol.ReceiverDirective{
		ProjectMode:      "selected",
		AllowedProjects:  []string{"proj-tw"},
		DiskPolicy:       protocol.DiskPolicyRollingWindow,
		ActiveDiskWindow: 3,
		StorageDirs:      roots,
		MaxDiskUsagePct:  99.0,
	}, nil)
	if got := ag.effectiveMaxDiskUsagePct(); got != 99.0 {
		t.Fatalf("expected hot-updated receiver watermark 99%%, got %.1f", got)
	}
	ag.applyDirective(&protocol.ReceiverDirective{
		ProjectMode:      "selected",
		AllowedProjects:  []string{"proj-tw"},
		DiskPolicy:       protocol.DiskPolicyRollingWindow,
		ActiveDiskWindow: 3,
		StorageDirs:      roots,
		MaxDiskUsagePct:  1.0,
	}, nil)
	if got := ag.effectiveMaxDiskUsagePct(); got != 1.0 {
		t.Fatalf("expected hot-updated receiver watermark 1%%, got %.1f", got)
	}
}

func TestUniversalDiskAffinityAcrossAllPolicies(t *testing.T) {
	base := t.TempDir()
	roots := make([]string, 4)
	for i := range roots {
		roots[i] = filepath.Join(base, fmt.Sprintf("disk%d", i+1))
		if err := os.MkdirAll(roots[i], 0o755); err != nil {
			t.Fatalf("mkdir disk%d: %v", i+1, err)
		}
	}

	cfg := Config{
		NodeID:      "b-aff",
		CenterURL:   "https://127.0.0.1:8440",
		CenterToken: "tok",
		StorageDirs: roots,
		StateDir:    filepath.Join(base, "state"),
	}
	cfg.ApplyDefaults()
	if !cfg.DiskAffinityEnabled() {
		t.Fatalf("expected disk_affinity default to be true")
	}

	// Test paired assets stay on the exact same disk across ALL policies when disk_affinity=true.
	for _, pol := range []string{
		protocol.DiskPolicyRoundRobin,
		protocol.DiskPolicyMostFree,
		protocol.DiskPolicyFirst,
		protocol.DiskPolicyRollingWindow,
		protocol.DiskPolicyAffinityHash,
	} {
		ag := &Agent{
			cfg:              &cfg,
			logger:           slog.Default(),
			discCache:        make(map[string]cachedDiscover),
			wakeupCh:         make(chan string, 16),
			diskHealth:       transfer.NewDiskHealthTracker(),
			maxDiskUsagePct:  99.0,
			activeDiskWindow: 3,
		}
		affOn := true
		ag.applyDirective(&protocol.ReceiverDirective{
			ProjectMode:      "selected",
			AllowedProjects:  []string{"tw-audio"},
			DiskPolicy:       pol,
			DiskAffinity:     &affOn,
			ActiveDiskWindow: 3,
			StorageDirs:      roots,
			MaxDiskUsagePct:  99.0,
		}, nil)

		dMedia := ag.chooseDestDir("tw-audio", "vid001.m4a", 1024)
		dInfo := ag.chooseDestDir("tw-audio", "vid001.info.json", 512)
		dSub := ag.chooseDestDir("tw-audio", "vid001.zh.vtt", 256)
		if dMedia == "" || dMedia != dInfo || dMedia != dSub {
			t.Fatalf("policy=%s with disk_affinity=true: paired files split across disks: m4a=%s info=%s vtt=%s", pol, dMedia, dInfo, dSub)
		}
	}

	// When disk_affinity=false under round_robin, paired files do NOT stick to the same disk.
	agOff := &Agent{
		cfg:             &cfg,
		logger:          slog.Default(),
		discCache:       make(map[string]cachedDiscover),
		wakeupCh:        make(chan string, 16),
		diskHealth:      transfer.NewDiskHealthTracker(),
		maxDiskUsagePct: 99.0,
	}
	affOff := false
	agOff.applyDirective(&protocol.ReceiverDirective{
		ProjectMode:     "selected",
		AllowedProjects: []string{"tw-audio"},
		DiskPolicy:      protocol.DiskPolicyRoundRobin,
		DiskAffinity:    &affOff,
		StorageDirs:     roots,
		MaxDiskUsagePct: 99.0,
	}, nil)
	d1 := agOff.chooseDestDir("tw-audio", "vid002.m4a", 1024)
	d2 := agOff.chooseDestDir("tw-audio", "vid002.info.json", 512)
	if d1 == d2 {
		t.Fatalf("expected round_robin with disk_affinity=false to alternate disks even for same stem, got %s twice", d1)
	}
}
