package center

import (
	"context"
	"math/rand/v2"
	"sort"
	"sync"
	"time"

	"relay-download/internal/protocol"
)

type LiveAState struct {
	NodeID               string
	Name                 string
	PublicAddr           string
	Projects             []string
	Version              string
	OS                   string
	Arch                 string
	DiskTotalBytes       uint64
	DiskFreeBytes        uint64
	DiskUsedPct          float64
	DiskAlarm            bool
	ActiveStreams        int
	MaxConcurrentStreams int
	Availability         map[string]protocol.ProjectAvailability // project_id -> availability
	LastSeen             time.Time
}

type LiveBState struct {
	NodeID              string
	Name                string
	Projects            []string
	StorageDirs         []string
	Disks               []protocol.DiskStatus
	ProjectSchedule     string
	DiskPolicy          string
	ConcurrencyMode     string
	EffectiveConcurrent int
	MaxConcurrentCap    int
	EffectiveStreams    int
	EffectiveRateMBps   float64
	AdaptiveState       string
	AdaptiveReason      string
	Version             string
	OS                  string
	Arch                string
	DiskTotalBytes      uint64
	DiskFreeBytes       uint64
	DiskUsedPct         float64
	ActiveCount         int
	LastSeen            time.Time
}

type bSub struct {
	ch     chan string
	cancel context.CancelFunc
}

// Hub maintains purely in-memory live availability and B wakeup SSE subscribers.
// No file lists are stored here; only per-(project, A-node) ready counts.
type Hub struct {
	mu             sync.RWMutex
	offlineTimeout time.Duration
	aNodes         map[string]*LiveAState
	bNodes         map[string]*LiveBState
	// projectID -> bNodeID -> wakeup subscription
	bSubs map[string]map[string]*bSub
}

func NewHub(offlineTimeout time.Duration) *Hub {
	return &Hub{
		offlineTimeout: offlineTimeout,
		aNodes:         make(map[string]*LiveAState),
		bNodes:         make(map[string]*LiveBState),
		bSubs:          make(map[string]map[string]*bSub),
	}
}

func (h *Hub) UpdateA(hb protocol.AgentAHeartbeatReq) {
	now := time.Now().UTC()
	availMap := make(map[string]protocol.ProjectAvailability, len(hb.Availability))
	var wakeupProjects []protocol.ProjectAvailability

	h.mu.Lock()
	for _, av := range hb.Availability {
		availMap[av.ProjectID] = av
		if av.ReadyCount > 0 {
			wakeupProjects = append(wakeupProjects, av)
		}
	}
	h.aNodes[hb.NodeID] = &LiveAState{
		NodeID:               hb.NodeID,
		Name:                 hb.Name,
		PublicAddr:           hb.PublicAddr,
		Projects:             append([]string(nil), hb.Projects...),
		Version:              hb.Version,
		OS:                   hb.OS,
		Arch:                 hb.Arch,
		DiskTotalBytes:       hb.DiskTotalBytes,
		DiskFreeBytes:        hb.DiskFreeBytes,
		DiskUsedPct:          hb.DiskUsedPct,
		DiskAlarm:            hb.DiskAlarm,
		ActiveStreams:        hb.ActiveStreams,
		MaxConcurrentStreams: hb.MaxConcurrentStreams,
		Availability:         availMap,
		LastSeen:             now,
	}
	h.mu.Unlock()

	for _, av := range wakeupProjects {
		h.WakeupB(av.ProjectID, av.ReadyCount)
	}
}

func (h *Hub) UpdateB(hb protocol.AgentBHeartbeatReq) {
	now := time.Now().UTC()
	activeCnt := hb.ActiveCount
	if activeCnt == 0 && len(hb.LegacyActiveTransfers) > 0 {
		activeCnt = len(hb.LegacyActiveTransfers)
	}
	h.mu.Lock()
	h.bNodes[hb.NodeID] = &LiveBState{
		NodeID:              hb.NodeID,
		Name:                hb.Name,
		Projects:            append([]string(nil), hb.Projects...),
		StorageDirs:         append([]string(nil), hb.StorageDirs...),
		Disks:               append([]protocol.DiskStatus(nil), hb.Disks...),
		ProjectSchedule:     hb.ProjectSchedule,
		DiskPolicy:          hb.DiskPolicy,
		ConcurrencyMode:     hb.ConcurrencyMode,
		EffectiveConcurrent: hb.EffectiveConcurrent,
		MaxConcurrentCap:    hb.MaxConcurrentCap,
		EffectiveStreams:    hb.EffectiveStreams,
		EffectiveRateMBps:   hb.EffectiveRateMBps,
		AdaptiveState:       hb.AdaptiveState,
		AdaptiveReason:      hb.AdaptiveReason,
		Version:             hb.Version,
		OS:                  hb.OS,
		Arch:                hb.Arch,
		DiskTotalBytes:      hb.DiskTotalBytes,
		DiskFreeBytes:       hb.DiskFreeBytes,
		DiskUsedPct:         hb.DiskUsedPct,
		ActiveCount:         activeCnt,
		LastSeen:            now,
	}
	h.mu.Unlock()
}

func (h *Hub) SubscribeB(bNodeID string, projects []string, cancel context.CancelFunc) (<-chan string, func()) {
	sub := &bSub{ch: make(chan string, 16), cancel: cancel}
	h.mu.Lock()
	for _, p := range projects {
		if _, ok := h.bSubs[p]; !ok {
			h.bSubs[p] = make(map[string]*bSub)
		}
		h.bSubs[p][bNodeID] = sub
	}
	h.mu.Unlock()

	unsub := func() {
		h.mu.Lock()
		for _, p := range projects {
			if m, ok := h.bSubs[p]; ok {
				if cur, exists := m[bNodeID]; exists && cur == sub {
					delete(m, bNodeID)
				}
				if len(m) == 0 {
					delete(h.bSubs, p)
				}
			}
		}
		h.mu.Unlock()
	}
	return sub.ch, unsub
}

// DisconnectSSE cancels any active SSE subscriptions for nodeID (e.g. on token rotation).
func (h *Hub) DisconnectSSE(nodeID string) {
	var cancels []context.CancelFunc
	seen := make(map[*bSub]struct{})

	h.mu.Lock()
	for p, m := range h.bSubs {
		if sub, ok := m[nodeID]; ok {
			delete(m, nodeID)
			if len(m) == 0 {
				delete(h.bSubs, p)
			}
			if _, dup := seen[sub]; !dup {
				seen[sub] = struct{}{}
				if sub.cancel != nil {
					cancels = append(cancels, sub.cancel)
				}
			}
		}
	}
	h.mu.Unlock()

	for _, c := range cancels {
		c()
	}
}

// RemoveNode evicts a deleted node from in-memory state and disconnects any active SSE streams.
func (h *Hub) RemoveNode(nodeID string) {
	h.mu.Lock()
	delete(h.aNodes, nodeID)
	delete(h.bNodes, nodeID)
	h.mu.Unlock()
	h.DisconnectSSE(nodeID)
}

// UpdateNodeProjects updates in-memory project restrictions for a node and disconnects its SSE
// streams so updated single-project / multi-project subscriptions take effect immediately.
func (h *Hub) UpdateNodeProjects(nodeID string, projects []string) {
	h.mu.Lock()
	if st, ok := h.aNodes[nodeID]; ok {
		st.Projects = append([]string(nil), projects...)
	}
	if st, ok := h.bNodes[nodeID]; ok {
		st.Projects = append([]string(nil), projects...)
	}
	h.mu.Unlock()
	h.DisconnectSSE(nodeID)
}

// WakeupB wakes up at most readyCount+1 subscribed B nodes for projectID (including wildcard "*"
// subscribers running in all-projects mode), preferring currently idle B nodes to prevent thundering herd.
func (h *Hub) WakeupB(projectID string, readyCount int) {
	type subInfo struct {
		bNodeID string
		active  int
		ch      chan string
	}
	h.mu.RLock()
	subsMap := h.bSubs[projectID]
	wildMap := h.bSubs["*"]
	if len(subsMap) == 0 && len(wildMap) == 0 {
		h.mu.RUnlock()
		return
	}
	seen := make(map[string]struct{}, len(subsMap)+len(wildMap))
	subs := make([]subInfo, 0, len(subsMap)+len(wildMap))
	addSub := func(bID string, sub *bSub) {
		if _, dup := seen[bID]; dup {
			return
		}
		seen[bID] = struct{}{}
		active := 0
		if st, ok := h.bNodes[bID]; ok {
			active = st.ActiveCount
		}
		subs = append(subs, subInfo{bNodeID: bID, active: active, ch: sub.ch})
	}
	for bID, sub := range subsMap {
		addSub(bID, sub)
	}
	for bID, sub := range wildMap {
		addSub(bID, sub)
	}
	h.mu.RUnlock()

	// Shuffle first for fair tie-breaking, then stably sort by active transfer count ascending.
	rand.Shuffle(len(subs), func(i, j int) { subs[i], subs[j] = subs[j], subs[i] })
	sort.SliceStable(subs, func(i, j int) bool {
		return subs[i].active < subs[j].active
	})

	limit := readyCount + 1
	if limit > len(subs) {
		limit = len(subs)
	}
	for i := 0; i < limit; i++ {
		select {
		case subs[i].ch <- projectID:
		default:
		}
	}
}

func (h *Hub) IsOnline(lastSeen time.Time) bool {
	return !lastSeen.IsZero() && time.Since(lastSeen) <= h.offlineTimeout
}

// DiscoverCandidates returns online A nodes that currently have ready_count > 0 for projectID,
// shuffled to spread preemptive B load across A1/A2/A3.
func (h *Hub) DiscoverCandidates(projectID string) []protocol.DiscoverCandidate {
	h.mu.RLock()
	list := make([]protocol.DiscoverCandidate, 0)
	for _, st := range h.aNodes {
		if !h.IsOnline(st.LastSeen) {
			continue
		}
		av, ok := st.Availability[projectID]
		if !ok || av.ReadyCount <= 0 {
			continue
		}
		list = append(list, protocol.DiscoverCandidate{
			ANodeID:    st.NodeID,
			AName:      st.Name,
			PublicAddr: st.PublicAddr,
			ReadyCount: av.ReadyCount,
			ReadyBytes: av.ReadyBytes,
		})
	}
	h.mu.RUnlock()

	rand.Shuffle(len(list), func(i, j int) { list[i], list[j] = list[j], list[i] })
	return list
}

func (h *Hub) GetLiveA(nodeID string) (*LiveAState, bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	st, ok := h.aNodes[nodeID]
	if !ok {
		return nil, false
	}
	cp := *st
	cp.Availability = make(map[string]protocol.ProjectAvailability, len(st.Availability))
	for k, v := range st.Availability {
		cp.Availability[k] = v
	}
	return &cp, true
}

func (h *Hub) Snapshot() (map[string]*LiveAState, map[string]*LiveBState) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	aOut := make(map[string]*LiveAState, len(h.aNodes))
	for k, st := range h.aNodes {
		cp := *st
		cp.Availability = make(map[string]protocol.ProjectAvailability, len(st.Availability))
		for pk, pv := range st.Availability {
			cp.Availability[pk] = pv
		}
		aOut[k] = &cp
	}
	bOut := make(map[string]*LiveBState, len(h.bNodes))
	for k, st := range h.bNodes {
		cp := *st
		cp.Projects = append([]string(nil), st.Projects...)
		cp.StorageDirs = append([]string(nil), st.StorageDirs...)
		cp.Disks = append([]protocol.DiskStatus(nil), st.Disks...)
		bOut[k] = &cp
	}
	return aOut, bOut
}

// ActiveReceiversByProject builds the deterministic sorted list of online receiver node IDs
// eligible for each project so all dispatch nodes compute the exact same HRW asset-group owner.
func (h *Hub) ActiveReceiversByProject(projectIDs []string, dbNodes []protocol.NodeRecord) map[string][]string {
	nodePolicy := make(map[string][]string, len(dbNodes))
	for _, n := range dbNodes {
		if n.Role == protocol.RoleAgentB {
			nodePolicy[n.ID] = n.Projects
		}
	}

	h.mu.RLock()
	onlineB := make([]*LiveBState, 0, len(h.bNodes))
	for _, st := range h.bNodes {
		if h.IsOnline(st.LastSeen) {
			onlineB = append(onlineB, st)
		}
	}
	h.mu.RUnlock()

	res := make(map[string][]string, len(projectIDs))
	for _, pid := range projectIDs {
		var ids []string
		for _, bSt := range onlineB {
			dbProjs, known := nodePolicy[bSt.NodeID]
			if known && !nodeAllowsProject(dbProjs, pid) {
				continue
			}
			if !nodeAllowsProject(bSt.Projects, pid) {
				continue
			}
			ids = append(ids, bSt.NodeID)
		}
		if len(ids) > 0 {
			sort.Strings(ids)
			res[pid] = ids
		}
	}
	return res
}

// ComputeClusterQuotas calculates smart per-receiver concurrency, stream, and rate ceilings
// based on node overrides, project-wide cluster limits, and online dispatch-node stream capacity.
func (h *Hub) ComputeClusterQuotas(node *StoredNode, projects []protocol.Project, dbNodes []protocol.NodeRecord) (maxConc int, suggestedStreamCap int, rateLimitMBps float64) {
	maxConc = node.MaxConcurrentOverride
	rateLimitMBps = node.RateLimitMBps

	nodePolicy := make(map[string][]string, len(dbNodes))
	for _, n := range dbNodes {
		if n.Role == protocol.RoleAgentB {
			nodePolicy[n.ID] = n.Projects
		}
	}

	h.mu.RLock()
	var totalDispatchStreams int
	for _, aSt := range h.aNodes {
		if h.IsOnline(aSt.LastSeen) && aSt.MaxConcurrentStreams > 0 {
			totalDispatchStreams += aSt.MaxConcurrentStreams
		}
	}
	onlineB := make([]*LiveBState, 0, len(h.bNodes))
	for _, bSt := range h.bNodes {
		if h.IsOnline(bSt.LastSeen) {
			onlineB = append(onlineB, bSt)
		}
	}
	h.mu.RUnlock()

	// Cluster-wide dispatch stream protection when multiple receivers share the same source pool.
	if totalDispatchStreams > 0 {
		if len(onlineB) <= 1 {
			suggestedStreamCap = totalDispatchStreams
		} else {
			// Fair share + 25% work-conserving headroom so active nodes absorb idle peer slack.
			share := int(float64(totalDispatchStreams)*1.25/float64(len(onlineB)) + 0.5)
			if share < 16 {
				share = 16
			}
			suggestedStreamCap = share
		}
	}

	// Project-level global concurrency & bandwidth quotas evenly divided across online peers.
	for _, proj := range projects {
		if !nodeAllowsProject(node.Projects, proj.ID) {
			continue
		}
		if proj.MaxTotalConcurrent <= 0 && proj.MaxTotalRateMBps <= 0 {
			continue
		}
		peers := 0
		selfCounted := false
		for _, bSt := range onlineB {
			if dbP, ok := nodePolicy[bSt.NodeID]; ok && !nodeAllowsProject(dbP, proj.ID) {
				continue
			}
			if !nodeAllowsProject(bSt.Projects, proj.ID) {
				continue
			}
			peers++
			if bSt.NodeID == node.ID {
				selfCounted = true
			}
		}
		if !selfCounted {
			peers++
		}
		if peers < 1 {
			peers = 1
		}
		if proj.MaxTotalConcurrent > 0 {
			share := (proj.MaxTotalConcurrent + peers - 1) / peers
			if share < 1 {
				share = 1
			}
			if maxConc == 0 || share < maxConc {
				maxConc = share
			}
		}
		if proj.MaxTotalRateMBps > 0 {
			share := proj.MaxTotalRateMBps / float64(peers)
			if rateLimitMBps == 0 || share < rateLimitMBps {
				rateLimitMBps = share
			}
		}
	}
	return maxConc, suggestedStreamCap, rateLimitMBps
}
