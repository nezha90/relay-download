package agentb

import (
	"context"
	"math"
	"sync"
	"sync/atomic"
	"time"

	"relay-download/internal/protocol"
)

// DynamicGate is a resizable concurrency semaphore supporting non-blocking try-acquire,
// context-aware blocking acquire, and live limit adjustments without dropping in-flight work.
type DynamicGate struct {
	mu       sync.Mutex
	limit    int
	inFlight int
	notify   chan struct{}
}

func NewDynamicGate(limit int) *DynamicGate {
	if limit < 1 {
		limit = 1
	}
	return &DynamicGate{
		limit:  limit,
		notify: make(chan struct{}),
	}
}

func (g *DynamicGate) broadcastLocked() {
	close(g.notify)
	g.notify = make(chan struct{})
}

func (g *DynamicGate) TryAcquire() bool {
	g.mu.Lock()
	if g.inFlight < g.limit {
		g.inFlight++
		g.mu.Unlock()
		return true
	}
	g.mu.Unlock()
	return false
}

func (g *DynamicGate) Acquire(ctx context.Context) error {
	for {
		g.mu.Lock()
		if g.inFlight < g.limit {
			g.inFlight++
			g.mu.Unlock()
			return nil
		}
		ch := g.notify
		g.mu.Unlock()

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ch:
		}
	}
}

func (g *DynamicGate) Release() {
	g.mu.Lock()
	if g.inFlight > 0 {
		g.inFlight--
	}
	if g.inFlight < g.limit {
		g.broadcastLocked()
	}
	g.mu.Unlock()
}

func (g *DynamicGate) SetLimit(limit int) {
	if limit < 1 {
		limit = 1
	}
	g.mu.Lock()
	old := g.limit
	g.limit = limit
	if limit > old && g.inFlight < g.limit {
		g.broadcastLocked()
	}
	g.mu.Unlock()
}

func (g *DynamicGate) Limit() int {
	g.mu.Lock()
	n := g.limit
	g.mu.Unlock()
	return n
}

func (g *DynamicGate) InFlight() int {
	g.mu.Lock()
	n := g.inFlight
	g.mu.Unlock()
	return n
}

func (g *DynamicGate) Free() int {
	g.mu.Lock()
	free := g.limit - g.inFlight
	g.mu.Unlock()
	if free < 0 {
		return 0
	}
	return free
}

// AdaptiveSnapshot captures the live controller status reported to Center heartbeats and Web UI.
type AdaptiveSnapshot struct {
	Mode                string
	EffectiveConcurrent int
	MaxConcurrentCap    int
	EffectiveStreams    int
	State               string // "probing" | "cruising" | "backoff" | "manual"
	Reason              string
}

// AdaptiveController implements a closed-loop BBR/Gradient + AIMD concurrency controller:
// - Probes upward while throughput scales with concurrency
// - Locks into a steady cruise sweet spot when the link or disk saturates (plateau detection)
// - Steps back immediately (AIMD multiplicative decrease) on 503 backpressure, high timeout/error
//   rate, or syncfs pending-ACK disk backlog
// - Periodically re-probes every 60s to reclaim bandwidth freed by peer nodes or network changes.
type AdaptiveController struct {
	workGate   *DynamicGate
	streamGate *DynamicGate

	epochBytes        atomic.Int64
	epochCompleted    atomic.Int64
	epochBackpressure atomic.Int64
	epochErrors       atomic.Int64

	mu                 sync.Mutex
	mode               string
	localMaxConc       int
	localMaxStreams    int
	streamRatio        float64
	minConc            int
	maxCap             int
	suggestedStreamCap int

	currentConc      int
	currentStreams   int
	sweetSpot        int
	state            string
	reason           string
	ewmaGoodput      float64
	bestGoodput      float64
	probeBaseGoodput float64
	cooldownEpochs   int
	cruiseEpochs     int
	lowGoodputStreak int
}

func NewAdaptiveController(mode string, localMaxConc, localMaxStreams int, workGate, streamGate *DynamicGate) *AdaptiveController {
	if localMaxConc < 1 {
		localMaxConc = 1
	}
	if localMaxStreams < localMaxConc {
		localMaxStreams = localMaxConc
	}
	if mode != protocol.ConcurrencyManual {
		mode = protocol.ConcurrencyAuto
	}
	ratio := float64(localMaxStreams) / float64(localMaxConc)
	if ratio < 1.0 {
		ratio = 1.0
	}
	if ratio > 8.0 {
		ratio = 8.0
	}
	minC := computeMinConc(localMaxConc)
	initConc := localMaxConc
	state := "manual"
	reason := "固定并发上限"
	if mode == protocol.ConcurrencyAuto {
		// Warm start at half of cap (at least minConc) so high-RTT links ramp to 1Gbps+ quickly.
		initConc = localMaxConc / 2
		if initConc < minC {
			initConc = minC
		}
		if localMaxConc <= 8 {
			initConc = localMaxConc
		}
		state = "probing"
		reason = "启动探优中"
	}
	initStreams := computeStreamLimit(initConc, ratio, localMaxStreams, 0)
	if workGate != nil {
		workGate.SetLimit(initConc)
	}
	if streamGate != nil {
		streamGate.SetLimit(initStreams)
	}
	return &AdaptiveController{
		workGate:        workGate,
		streamGate:      streamGate,
		mode:            mode,
		localMaxConc:    localMaxConc,
		localMaxStreams: localMaxStreams,
		streamRatio:     ratio,
		minConc:         minC,
		maxCap:          localMaxConc,
		currentConc:     initConc,
		currentStreams:  initStreams,
		sweetSpot:       initConc,
		state:           state,
		reason:          reason,
	}
}

func computeMinConc(maxCap int) int {
	if maxCap <= 4 {
		return 1
	}
	m := maxCap / 6
	if m < 4 {
		m = 4
	}
	if m > 32 {
		m = 32
	}
	if m > maxCap {
		m = maxCap
	}
	return m
}

func computeStreamLimit(conc int, ratio float64, localMaxStreams, suggestedCap int) int {
	streams := int(math.Round(float64(conc) * ratio))
	if streams < conc {
		streams = conc
	}
	capLimit := localMaxStreams
	if capLimit < conc {
		capLimit = conc
	}
	if suggestedCap > 0 && suggestedCap < capLimit {
		capLimit = suggestedCap
	}
	if capLimit > 1024 {
		capLimit = 1024
	}
	if streams > capLimit {
		streams = capLimit
	}
	if streams < 1 {
		streams = 1
	}
	return streams
}

func (c *AdaptiveController) RecordBytes(n int64) {
	if c != nil && n > 0 {
		c.epochBytes.Add(n)
	}
}

func (c *AdaptiveController) RecordCompleted() {
	if c != nil {
		c.epochCompleted.Add(1)
	}
}

func (c *AdaptiveController) RecordBackpressure() {
	if c != nil {
		c.epochBackpressure.Add(1)
	}
}

func (c *AdaptiveController) RecordError() {
	if c != nil {
		c.epochErrors.Add(1)
	}
}

// Configure updates runtime bounds and mode pushed from Center directives without restart.
func (c *AdaptiveController) Configure(mode string, maxConcOverride, suggestedStreamCap int) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	if mode == protocol.ConcurrencyAuto || mode == protocol.ConcurrencyManual {
		c.mode = mode
	}
	newCap := c.localMaxConc
	if maxConcOverride > 0 {
		newCap = maxConcOverride
		if newCap > 1024 {
			newCap = 1024
		}
	}
	c.maxCap = newCap
	c.minConc = computeMinConc(newCap)
	c.suggestedStreamCap = suggestedStreamCap

	if c.mode == protocol.ConcurrencyManual {
		c.currentConc = newCap
		c.sweetSpot = newCap
		c.state = "manual"
		c.reason = "手动固定并发"
	} else {
		if c.currentConc > newCap {
			c.currentConc = newCap
		}
		if c.currentConc < c.minConc {
			c.currentConc = c.minConc
		}
		if c.sweetSpot > newCap {
			c.sweetSpot = newCap
		}
		if c.state == "manual" {
			c.state = "probing"
			c.reason = "已切换智能自适应，探优中"
			c.probeBaseGoodput = 0
		}
	}
	c.currentStreams = computeStreamLimit(c.currentConc, c.streamRatio, max(c.localMaxStreams, c.maxCap), c.suggestedStreamCap)
	c.applyGatesLocked()
}

func (c *AdaptiveController) applyGatesLocked() {
	if c.workGate != nil {
		c.workGate.SetLimit(c.currentConc)
	}
	if c.streamGate != nil {
		c.streamGate.SetLimit(c.currentStreams)
	}
}

func (c *AdaptiveController) Snapshot() AdaptiveSnapshot {
	if c == nil {
		return AdaptiveSnapshot{}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return AdaptiveSnapshot{
		Mode:                c.mode,
		EffectiveConcurrent: c.currentConc,
		MaxConcurrentCap:    c.maxCap,
		EffectiveStreams:    c.currentStreams,
		State:               c.state,
		Reason:              c.reason,
	}
}

// Evaluate runs one closed-loop control step for an elapsed window dt.
func (c *AdaptiveController) Evaluate(dt time.Duration, inFlight int, pendingAcks int64) AdaptiveSnapshot {
	if c == nil {
		return AdaptiveSnapshot{}
	}
	bytes := c.epochBytes.Swap(0)
	completed := c.epochCompleted.Swap(0)
	bp503 := c.epochBackpressure.Swap(0)
	errs := c.epochErrors.Swap(0)

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.mode == protocol.ConcurrencyManual {
		c.currentConc = c.maxCap
		c.currentStreams = computeStreamLimit(c.currentConc, c.streamRatio, max(c.localMaxStreams, c.maxCap), c.suggestedStreamCap)
		c.state = "manual"
		c.reason = "手动固定并发"
		c.applyGatesLocked()
		return AdaptiveSnapshot{
			Mode:                c.mode,
			EffectiveConcurrent: c.currentConc,
			MaxConcurrentCap:    c.maxCap,
			EffectiveStreams:    c.currentStreams,
			State:               c.state,
			Reason:              c.reason,
		}
	}

	secs := dt.Seconds()
	if secs <= 0.1 {
		secs = 1.0
	}
	goodput := float64(bytes) / secs
	if c.ewmaGoodput == 0 {
		c.ewmaGoodput = goodput
	} else {
		c.ewmaGoodput = 0.35*goodput + 0.65*c.ewmaGoodput
	}
	// Gentle decay on historical peak so long-term network shifts are re-learned.
	c.bestGoodput *= 0.995

	// 1. Hard backpressure signals -> immediate multiplicative decrease (AIMD beta = 0.75).
	highErrs := errs >= 3 && errs*4 > max64(completed, 1)
	diskLag := pendingAcks > int64(max(128, c.currentConc*3))
	if bp503 > 0 || highErrs || diskLag {
		next := int(math.Floor(float64(c.currentConc) * 0.75))
		if next < c.minConc {
			next = c.minConc
		}
		c.currentConc = next
		c.sweetSpot = next
		c.state = "backoff"
		c.cooldownEpochs = 2
		c.cruiseEpochs = 0
		c.probeBaseGoodput = goodput
		switch {
		case bp503 > 0:
			c.reason = "分发端限流(503)，自动降载退避"
		case diskLag:
			c.reason = "本地磁盘落盘积压，自动降载保护"
		default:
			c.reason = "传输超时率升高，自动降载避障"
		}
		c.currentStreams = computeStreamLimit(c.currentConc, c.streamRatio, max(c.localMaxStreams, c.maxCap), c.suggestedStreamCap)
		c.applyGatesLocked()
		return c.snapshotLocked()
	}

	// 2. Post-backoff stabilization cooldown.
	if c.cooldownEpochs > 0 {
		c.cooldownEpochs--
		if c.cooldownEpochs == 0 {
			c.state = "probing"
			c.probeBaseGoodput = goodput
			c.reason = "退避稳定，恢复平滑探优"
		}
		return c.snapshotLocked()
	}

	// 3. Idle / under-utilized guard: do not inflate concurrency when queue isn't busy.
	if bytes == 0 && inFlight == 0 {
		c.state = "cruising"
		c.reason = "队列空闲待命"
		return c.snapshotLocked()
	}
	util := float64(inFlight) / float64(max(c.currentConc, 1))
	if util < 0.70 {
		if goodput > c.bestGoodput {
			c.bestGoodput = goodput
			c.sweetSpot = c.currentConc
		}
		c.state = "cruising"
		c.reason = "当前并发充足，稳态巡航"
		return c.snapshotLocked()
	}

	// 4. Saturated & healthy: gradient hill-climbing & plateau cruise.
	if c.state == "cruising" {
		c.cruiseEpochs++
		if c.bestGoodput > 0 && goodput < c.bestGoodput*0.82 {
			c.lowGoodputStreak++
		} else {
			c.lowGoodputStreak = 0
			if goodput > c.bestGoodput {
				c.bestGoodput = goodput
				c.sweetSpot = c.currentConc
			}
		}
		// Re-probe periodically (every 12 epochs ~60s) or promptly if sustained throughput dip while saturated.
		if c.currentConc < c.maxCap && (c.cruiseEpochs >= 12 || c.lowGoodputStreak >= 2) {
			c.cruiseEpochs = 0
			c.lowGoodputStreak = 0
			c.probeBaseGoodput = goodput
			c.sweetSpot = c.currentConc
			step := clampInt(int(math.Ceil(float64(c.currentConc)*0.10)), 2, 32)
			c.currentConc = min(c.maxCap, c.currentConc+step)
			c.state = "probing"
			c.reason = "周期探优，检测可用剩余带宽"
			c.currentStreams = computeStreamLimit(c.currentConc, c.streamRatio, max(c.localMaxStreams, c.maxCap), c.suggestedStreamCap)
			c.applyGatesLocked()
		}
		return c.snapshotLocked()
	}

	// Currently in "probing" state: compare new goodput against pre-probe baseline.
	if c.probeBaseGoodput <= 0 || goodput >= c.probeBaseGoodput*1.03 {
		if goodput > c.bestGoodput {
			c.bestGoodput = goodput
		}
		c.sweetSpot = c.currentConc
		c.probeBaseGoodput = goodput
		if c.currentConc < c.maxCap {
			step := clampInt(int(math.Ceil(float64(c.currentConc)*0.15)), 2, 40)
			c.currentConc = min(c.maxCap, c.currentConc+step)
			c.state = "probing"
			c.reason = "吞吐随并发提升，继续探优"
		} else {
			c.state = "cruising"
			c.cruiseEpochs = 0
			c.reason = "已达上限且健康，稳态巡航"
		}
	} else if goodput < c.probeBaseGoodput*0.90 {
		// Congestion cliff detected: step back to sweetSpot (or -15%).
		back := int(math.Floor(float64(c.currentConc) * 0.85))
		if c.sweetSpot >= c.minConc && c.sweetSpot < back {
			back = c.sweetSpot
		}
		if back < c.minConc {
			back = c.minConc
		}
		c.currentConc = back
		c.state = "cruising"
		c.cooldownEpochs = 1
		c.cruiseEpochs = 0
		c.reason = "检测到拥塞拐点，回调至最优并发"
	} else {
		// Plateau (0.90 .. 1.03): bandwidth ceiling saturated -> park at lower sweetSpot to save sockets.
		if c.sweetSpot >= c.minConc && c.sweetSpot <= c.currentConc {
			c.currentConc = c.sweetSpot
		}
		c.state = "cruising"
		c.cruiseEpochs = 0
		c.reason = "带宽趋于饱和，锁定最优巡航"
	}

	c.currentStreams = computeStreamLimit(c.currentConc, c.streamRatio, max(c.localMaxStreams, c.maxCap), c.suggestedStreamCap)
	c.applyGatesLocked()
	return c.snapshotLocked()
}

func (c *AdaptiveController) snapshotLocked() AdaptiveSnapshot {
	return AdaptiveSnapshot{
		Mode:                c.mode,
		EffectiveConcurrent: c.currentConc,
		MaxConcurrentCap:    c.maxCap,
		EffectiveStreams:    c.currentStreams,
		State:               c.state,
		Reason:              c.reason,
	}
}

func clampInt(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func max64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}
