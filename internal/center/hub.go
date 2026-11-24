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
	NodeID         string
	Name           string
	PublicAddr     string
	Projects       []string
	DiskTotalBytes uint64
	DiskFreeBytes  uint64
	DiskUsedPct    float64
	DiskAlarm      bool
	ActiveStreams  int
	OutSpeedBps    int64
	Availability   map[string]protocol.ProjectAvailability // project_id -> availability
	LastSeen       time.Time
}

type LiveBState struct {
	NodeID          string
	Name            string
	Projects        []string
	DiskTotalBytes  uint64
	DiskFreeBytes   uint64
	DiskUsedPct     float64
	ActiveTransfers []protocol.BActiveTransfer
	InSpeedBps      int64
	LastSeen        time.Time
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
		NodeID:         hb.NodeID,
		Name:           hb.Name,
		PublicAddr:     hb.PublicAddr,
		Projects:       append([]string(nil), hb.Projects...),
		DiskTotalBytes: hb.DiskTotalBytes,
		DiskFreeBytes:  hb.DiskFreeBytes,
		DiskUsedPct:    hb.DiskUsedPct,
		DiskAlarm:      hb.DiskAlarm,
		ActiveStreams:  hb.ActiveStreams,
		OutSpeedBps:    hb.OutSpeedBps,
		Availability:   availMap,
		LastSeen:       now,
	}
	h.mu.Unlock()

	for _, av := range wakeupProjects {
		h.WakeupB(av.ProjectID, av.ReadyCount)
	}
}

func (h *Hub) UpdateB(hb protocol.AgentBHeartbeatReq) {
	now := time.Now().UTC()
	h.mu.Lock()
	h.bNodes[hb.NodeID] = &LiveBState{
		NodeID:          hb.NodeID,
		Name:            hb.Name,
		Projects:        append([]string(nil), hb.Projects...),
		DiskTotalBytes:  hb.DiskTotalBytes,
		DiskFreeBytes:   hb.DiskFreeBytes,
		DiskUsedPct:     hb.DiskUsedPct,
		ActiveTransfers: append([]protocol.BActiveTransfer(nil), hb.ActiveTransfers...),
		InSpeedBps:      hb.InSpeedBps,
		LastSeen:        now,
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

// RemoveNode evicts a deleted node from in-memory state and disconnects any active SSE streams.
func (h *Hub) RemoveNode(nodeID string) {
	var cancels []context.CancelFunc
	seen := make(map[*bSub]struct{})

	h.mu.Lock()
	delete(h.aNodes, nodeID)
	delete(h.bNodes, nodeID)
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

// WakeupB wakes up at most readyCount+1 subscribed B nodes for projectID,
// preferring currently idle B nodes to prevent thundering herd.
func (h *Hub) WakeupB(projectID string, readyCount int) {
	h.mu.RLock()
	subsMap := h.bSubs[projectID]
	if len(subsMap) == 0 {
		h.mu.RUnlock()
		return
	}
	type subInfo struct {
		bNodeID string
		active  int
		ch      chan string
	}
	subs := make([]subInfo, 0, len(subsMap))
	for bID, sub := range subsMap {
		active := 0
		if st, ok := h.bNodes[bID]; ok {
			active = len(st.ActiveTransfers)
		}
		subs = append(subs, subInfo{bNodeID: bID, active: active, ch: sub.ch})
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
		cp.ActiveTransfers = append([]protocol.BActiveTransfer(nil), st.ActiveTransfers...)
		bOut[k] = &cp
	}
	return aOut, bOut
}

func (h *Hub) ActiveANodesForProject(projectID string) []*LiveAState {
	h.mu.RLock()
	defer h.mu.RUnlock()
	var list []*LiveAState
	for _, st := range h.aNodes {
		if !h.IsOnline(st.LastSeen) {
			continue
		}
		av, ok := st.Availability[projectID]
		if ok && (av.ReadyCount > 0 || av.ClaimedCount > 0) {
			cp := *st
			list = append(list, &cp)
		}
	}
	return list
}
