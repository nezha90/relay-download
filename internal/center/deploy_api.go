package center

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"

	"relay-download/internal/auth"
	"relay-download/internal/deployer"
	"relay-download/internal/protocol"
	"relay-download/internal/transfer"
)

var validVersionRe = regexp.MustCompile(`^[A-Za-z0-9._+-]{1,64}$`)

func (s *Server) processNodeHeartbeatUpgrade(ctx context.Context, nodeID, nodeVersion, attemptID, agentStatus, agentErr string) protocol.HeartbeatResp {
	upg, err := s.store.GetNodeUpgrade(ctx, nodeID)
	if err != nil {
		return protocol.HeartbeatResp{}
	}

	// Node already restarted onto the target version -> mark upgrade completed!
	if nodeVersion != "" && nodeVersion == upg.TargetVersion {
		if upg.Status != "completed" {
			upg.Status = "completed"
			upg.Message = "已升级至 " + nodeVersion
			upg.UpdatedAt = time.Now().UTC()
			_ = s.store.UpsertNodeUpgrade(ctx, *upg)
		}
		return protocol.HeartbeatResp{}
	}

	// Update progress only if the agent status matches the active upgrade attempt.
	if attemptID != "" && attemptID == upg.AttemptID {
		switch agentStatus {
		case "downloading", "restarting":
			if upg.Status != agentStatus {
				upg.Status = agentStatus
				upg.Message = ""
				upg.UpdatedAt = time.Now().UTC()
				_ = s.store.UpsertNodeUpgrade(ctx, *upg)
			}
		case "failed":
			if upg.Status != "failed" {
				upg.Status = "failed"
				upg.Message = agentErr
				upg.UpdatedAt = time.Now().UTC()
				_ = s.store.UpsertNodeUpgrade(ctx, *upg)
			}
			return protocol.HeartbeatResp{}
		}
	}

	if upg.Status == "completed" || upg.Status == "failed" {
		return protocol.HeartbeatResp{}
	}

	rel, err := s.store.GetRelease(ctx, upg.ReleaseID)
	if err != nil {
		return protocol.HeartbeatResp{}
	}
	return protocol.HeartbeatResp{
		Upgrade: &protocol.UpgradeDirective{
			ReleaseID:   rel.ID,
			AttemptID:   upg.AttemptID,
			Version:     rel.Version,
			SHA256:      rel.SHA256,
			DownloadURL: "/api/v1/releases/" + rel.ID + "/download",
		},
	}
}

func (s *Server) releaseFilePath(filename string) string {
	return filepath.Join(s.cfg.ReleasesDir, filepath.Base(filename))
}

func (s *Server) handleAdminListReleases(w http.ResponseWriter, r *http.Request) {
	role := strings.TrimSpace(r.URL.Query().Get("role"))
	list, err := s.store.ListReleases(r.Context(), role)
	if err != nil {
		protocol.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	protocol.WriteJSON(w, http.StatusOK, list)
}

func (s *Server) handleAdminUploadRelease(w http.ResponseWriter, r *http.Request) {
	// Cap upload size at 256 MiB to prevent disk/memory exhaustion via oversized multipart uploads.
	r.Body = http.MaxBytesReader(w, r.Body, 256<<20)
	ct := r.Header.Get("Content-Type")
	if !strings.HasPrefix(ct, "multipart/form-data") {
		protocol.WriteError(w, http.StatusBadRequest, "multipart/form-data required")
		return
	}
	mr, err := r.MultipartReader()
	if err != nil {
		protocol.WriteError(w, http.StatusBadRequest, "invalid multipart upload: "+err.Error())
		return
	}

	var (
		role    string
		ver     string
		osName  = "linux"
		arch    = "amd64"
		notes   string
		sawFile bool
		written int64
		shaHex  string
		magic   [4]byte
	)

	relID := uuid.NewString()
	tmpPath := filepath.Join(s.cfg.ReleasesDir, relID+".tmp")
	if err := os.MkdirAll(s.cfg.ReleasesDir, 0o755); err != nil {
		protocol.WriteError(w, http.StatusInternalServerError, "mkdir releases_dir: "+err.Error())
		return
	}

	for {
		part, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			_ = os.Remove(tmpPath)
			protocol.WriteError(w, http.StatusBadRequest, "read multipart: "+err.Error())
			return
		}
		switch part.FormName() {
		case "role":
			b, _ := io.ReadAll(io.LimitReader(part, 64))
			role = strings.TrimSpace(string(b))
			_ = part.Close()
		case "version":
			b, _ := io.ReadAll(io.LimitReader(part, 128))
			ver = strings.TrimSpace(string(b))
			_ = part.Close()
		case "os":
			b, _ := io.ReadAll(io.LimitReader(part, 64))
			if v := strings.ToLower(strings.TrimSpace(string(b))); v != "" {
				osName = v
			}
			_ = part.Close()
		case "arch":
			b, _ := io.ReadAll(io.LimitReader(part, 64))
			if v := strings.ToLower(strings.TrimSpace(string(b))); v != "" {
				arch = v
			}
			_ = part.Close()
		case "notes":
			b, _ := io.ReadAll(io.LimitReader(part, 1024))
			notes = sanitizeSingleLine(string(b), 512)
			_ = part.Close()
		case "file":
			if sawFile {
				_ = part.Close()
				_ = os.Remove(tmpPath)
				protocol.WriteError(w, http.StatusBadRequest, "multiple file parts not supported")
				return
			}
			sawFile = true
			f, cErr := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
			if cErr != nil {
				_ = part.Close()
				protocol.WriteError(w, http.StatusInternalServerError, "create release file: "+cErr.Error())
				return
			}
			var copyErr error
			written, shaHex, copyErr = transfer.CopyStream(r.Context(), f, part, nil, nil)
			syncErr := f.Sync()
			closeErr := f.Close()
			_ = part.Close()
			if copyErr != nil || syncErr != nil || closeErr != nil {
				_ = os.Remove(tmpPath)
				protocol.WriteError(w, http.StatusInternalServerError, fmt.Sprintf("write release failed: %v %v %v", copyErr, syncErr, closeErr))
				return
			}
			if rf, rErr := os.Open(tmpPath); rErr == nil {
				_, _ = io.ReadFull(rf, magic[:])
				_ = rf.Close()
			}
		default:
			_ = part.Close()
		}
	}

	cleanupFail := func(status int, msg string) {
		_ = os.Remove(tmpPath)
		protocol.WriteError(w, status, msg)
	}
	if !sawFile || written == 0 {
		cleanupFail(http.StatusBadRequest, "binary file is required and must be non-empty")
		return
	}
	if role != protocol.RoleAgentA && role != protocol.RoleAgentB {
		cleanupFail(http.StatusBadRequest, "role must be agent_a or agent_b")
		return
	}
	if !validVersionRe.MatchString(ver) {
		cleanupFail(http.StatusBadRequest, "invalid version: only [A-Za-z0-9._+-] (1-64 chars) allowed")
		return
	}
	if osName != "linux" && osName != "darwin" {
		cleanupFail(http.StatusBadRequest, "os must be linux or darwin")
		return
	}
	if arch != "amd64" && arch != "arm64" {
		cleanupFail(http.StatusBadRequest, "arch must be amd64 or arm64")
		return
	}
	if osName == "linux" && !bytes.Equal(magic[:], []byte{0x7f, 'E', 'L', 'F'}) {
		cleanupFail(http.StatusBadRequest, "uploaded file is not a valid Linux ELF binary")
		return
	}

	finalName := fmt.Sprintf("%s-%s-%s-%s-%s.bin", role, ver, osName, arch, relID[:8])
	finalPath := s.releaseFilePath(finalName)
	if err := os.Rename(tmpPath, finalPath); err != nil {
		cleanupFail(http.StatusInternalServerError, "commit release file: "+err.Error())
		return
	}

	rec := protocol.ReleaseRecord{
		ID:        relID,
		Role:      role,
		Version:   ver,
		OS:        osName,
		Arch:      arch,
		SHA256:    shaHex,
		Size:      written,
		Filename:  finalName,
		Notes:     notes,
		CreatedAt: time.Now().UTC(),
	}
	if err := s.store.InsertRelease(r.Context(), rec); err != nil {
		_ = os.Remove(finalPath)
		protocol.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.logger.Info("release binary uploaded", "id", rec.ID, "role", rec.Role, "version", rec.Version, "platform", rec.OS+"/"+rec.Arch, "size", rec.Size)
	protocol.WriteJSON(w, http.StatusOK, rec)
}

func (s *Server) handleAdminDeleteRelease(w http.ResponseWriter, r *http.Request) {
	rec, err := s.store.DeleteRelease(r.Context(), r.PathValue("id"))
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			protocol.WriteError(w, http.StatusNotFound, "release not found")
			return
		}
		protocol.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = os.Remove(s.releaseFilePath(rec.Filename))
	w.WriteHeader(http.StatusNoContent)
}

// handleNodeDownloadRelease serves a release binary to an authenticated Agent A or B node matching the release role.
func (s *Server) handleNodeDownloadRelease(w http.ResponseWriter, r *http.Request, node *StoredNode) {
	rel, err := s.store.GetRelease(r.Context(), r.PathValue("id"))
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			protocol.WriteError(w, http.StatusNotFound, "release not found")
			return
		}
		protocol.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if rel.Role != node.Role {
		protocol.WriteError(w, http.StatusForbidden, "release role does not match node role")
		return
	}
	f, err := os.Open(s.releaseFilePath(rel.Filename))
	if err != nil {
		protocol.WriteError(w, http.StatusNotFound, "release binary file missing")
		return
	}
	defer f.Close()

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("X-Release-Version", rel.Version)
	w.Header().Set("X-Release-SHA256", rel.SHA256)
	w.Header().Set("Content-Length", fmt.Sprintf("%d", rel.Size))
	w.WriteHeader(http.StatusOK)
	_, _, _ = transfer.CopyStream(r.Context(), w, f, nil, nil)
}

func (s *Server) handleAdminBatchUpgrade(w http.ResponseWriter, r *http.Request) {
	var req protocol.BatchUpgradeReq
	if err := protocol.DecodeJSON(r.Body, &req); err != nil {
		protocol.WriteError(w, http.StatusBadRequest, "invalid json")
		return
	}
	if req.ReleaseID == "" || len(req.NodeIDs) == 0 {
		protocol.WriteError(w, http.StatusBadRequest, "release_id and node_ids are required")
		return
	}
	rel, err := s.store.GetRelease(r.Context(), req.ReleaseID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			protocol.WriteError(w, http.StatusNotFound, "release not found")
			return
		}
		protocol.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}

	aSnap, bSnap := s.hub.Snapshot()
	res := protocol.BatchUpgradeResult{
		Queued:  make([]string, 0, len(req.NodeIDs)),
		Skipped: make(map[string]string),
	}

	for _, nid := range req.NodeIDs {
		nid = strings.TrimSpace(nid)
		if nid == "" {
			continue
		}
		node, err := s.store.GetNode(r.Context(), nid)
		if err != nil {
			res.Skipped[nid] = "节点不存在"
			continue
		}
		if node.Role != rel.Role {
			roleLabel := func(r string) string {
				if r == protocol.RoleAgentA {
					return "分发节点"
				}
				return "接收节点"
			}
			res.Skipped[nid] = fmt.Sprintf("角色不匹配 (节点为%s，版本包为%s)", roleLabel(node.Role), roleLabel(rel.Role))
			continue
		}
		// Check platform match if node has reported OS/Arch in heartbeat.
		var nodeOS, nodeArch, nodeVer string
		if node.Role == protocol.RoleAgentA {
			if st, ok := aSnap[nid]; ok {
				nodeOS, nodeArch, nodeVer = st.OS, st.Arch, st.Version
			}
		} else {
			if st, ok := bSnap[nid]; ok {
				nodeOS, nodeArch, nodeVer = st.OS, st.Arch, st.Version
			}
		}
		if nodeOS != "" && nodeArch != "" && (nodeOS != rel.OS || nodeArch != rel.Arch) {
			res.Skipped[nid] = fmt.Sprintf("平台不匹配 (节点 %s/%s，版本包 %s/%s)", nodeOS, nodeArch, rel.OS, rel.Arch)
			continue
		}
		if nodeVer != "" && nodeVer == rel.Version {
			res.Skipped[nid] = "已是目标版本 " + rel.Version
			continue
		}
		upg := protocol.NodeUpgradeRecord{
			NodeID:        nid,
			ReleaseID:     rel.ID,
			AttemptID:     uuid.NewString(),
			TargetVersion: rel.Version,
			Status:        "pending",
			Message:       "等待节点心跳拉取更新",
			UpdatedAt:     time.Now().UTC(),
		}
		if err := s.store.UpsertNodeUpgrade(r.Context(), upg); err != nil {
			res.Skipped[nid] = err.Error()
			continue
		}
		res.Queued = append(res.Queued, nid)
	}
	protocol.WriteJSON(w, http.StatusOK, res)
}

func (s *Server) handleAdminCancelUpgrade(w http.ResponseWriter, r *http.Request) {
	_ = s.store.DeleteNodeUpgrade(r.Context(), r.PathValue("id"))
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleAdminDeployPrecheck(w http.ResponseWriter, r *http.Request) {
	var req protocol.DeployPrecheckReq
	if err := protocol.DecodeJSON(r.Body, &req); err != nil {
		protocol.WriteError(w, http.StatusBadRequest, "invalid json")
		return
	}
	finder := func(osName, arch string) (*protocol.ReleaseRecord, error) {
		if req.ReleaseID != "" {
			rel, err := s.store.GetRelease(r.Context(), req.ReleaseID)
			if err != nil {
				return nil, err
			}
			if rel.Role != protocol.RoleAgentA || rel.OS != osName || rel.Arch != arch {
				return nil, fmt.Errorf("selected release %s (%s %s/%s) does not match target %s/%s", rel.Version, rel.Role, rel.OS, rel.Arch, osName, arch)
			}
			return rel, nil
		}
		return s.store.LatestReleaseFor(r.Context(), protocol.RoleAgentA, osName, arch)
	}
	res, err := s.deployer.Precheck(r.Context(), req, finder)
	if err != nil {
		protocol.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	protocol.WriteJSON(w, http.StatusOK, res)
}

func (s *Server) handleAdminDeployAgentA(w http.ResponseWriter, r *http.Request) {
	var req protocol.DeployAgentAReq
	if err := protocol.DecodeJSON(r.Body, &req); err != nil {
		protocol.WriteError(w, http.StatusBadRequest, "invalid json")
		return
	}
	req.Host = strings.TrimSpace(req.Host)
	req.NodeID = strings.TrimSpace(req.NodeID)
	req.NodeName = strings.TrimSpace(req.NodeName)
	if err := deployer.ValidateHost(req.Host); err != nil {
		protocol.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !validIDRe.MatchString(req.NodeID) {
		protocol.WriteError(w, http.StatusBadRequest, "invalid node_id: only [A-Za-z0-9._-] (1-64 chars) allowed")
		return
	}
	if err := deployer.ValidateSafeSingleLine(req.NodeName, 128); err != nil {
		protocol.WriteError(w, http.StatusBadRequest, "invalid node_name: "+err.Error())
		return
	}
	cleanProjs := make([]string, 0, len(req.Projects))
	for _, pid := range req.Projects {
		pid = strings.TrimSpace(pid)
		if pid == "" {
			continue
		}
		if !validIDRe.MatchString(pid) {
			protocol.WriteError(w, http.StatusBadRequest, "invalid project id: "+pid)
			return
		}
		cleanProjs = append(cleanProjs, pid)
	}
	req.Projects = cleanProjs
	if s.cfg.CAKey == "" || s.cfg.CACert == "" || s.cfg.PublicURL == "" {
		protocol.WriteError(w, http.StatusBadRequest, "center config requires ca_cert, ca_key, and public_url for one-click deployment")
		return
	}
	if req.SSHPort <= 0 {
		req.SSHPort = 22
	}
	if req.PublicPort <= 0 {
		req.PublicPort = 8443
	}
	if req.LocalPort <= 0 {
		req.LocalPort = 18081
	}
	if req.SSHPort < 1 || req.SSHPort > 65535 || req.PublicPort < 1 || req.PublicPort > 65535 || req.LocalPort < 1 || req.LocalPort > 65535 || req.PublicPort == req.LocalPort {
		protocol.WriteError(w, http.StatusBadRequest, "invalid ssh_port / public_port / local_port")
		return
	}
	if req.InstallDir == "" {
		req.InstallDir = "/opt/relay-agent-a"
	}
	if req.DataDir == "" {
		req.DataDir = "/data/relay-a"
	}
	if err := deployer.ValidateAbsDir(req.InstallDir); err != nil {
		protocol.WriteError(w, http.StatusBadRequest, "install_dir: "+err.Error())
		return
	}
	if err := deployer.ValidateAbsDir(req.DataDir); err != nil {
		protocol.WriteError(w, http.StatusBadRequest, "data_dir: "+err.Error())
		return
	}

	var rel *protocol.ReleaseRecord
	var err error
	if req.ReleaseID != "" {
		rel, err = s.store.GetRelease(r.Context(), req.ReleaseID)
	} else {
		rel, err = s.store.LatestReleaseFor(r.Context(), protocol.RoleAgentA, "linux", "amd64")
	}
	if err != nil {
		protocol.WriteError(w, http.StatusBadRequest, "no matching agent_a release found: please upload a Linux agent_a binary first")
		return
	}
	if rel.Role != protocol.RoleAgentA {
		protocol.WriteError(w, http.StatusBadRequest, "selected release is not for agent_a")
		return
	}

	pubHost := req.Host
	if ip := net.ParseIP(req.Host); ip != nil && ip.To4() == nil {
		pubHost = "[" + req.Host + "]"
	}
	pubAddr := fmt.Sprintf("https://%s:%d", pubHost, req.PublicPort)

	task := &protocol.DeployTask{
		ID:             uuid.NewString(),
		NodeID:         req.NodeID,
		Host:           req.Host,
		Status:         "running",
		Step:           "init",
		Logs:           []string{fmt.Sprintf("[%s] 开始部署公网分发节点 %s -> %s", time.Now().Format("15:04:05"), req.NodeID, req.Host)},
		PublicAddr:     pubAddr,
		ReleaseVersion: rel.Version,
		StartedAt:      time.Now().UTC(),
	}
	s.putDeployTask(task)

	go s.runDeployAgentATask(task.ID, req, *rel, pubAddr)

	protocol.WriteJSON(w, http.StatusAccepted, s.cloneDeployTask(task.ID))
}

func (s *Server) runDeployAgentATask(taskID string, req protocol.DeployAgentAReq, rel protocol.ReleaseRecord, pubAddr string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	appendLog := func(step, msg string) {
		s.deployMu.Lock()
		if t, ok := s.deployTasks[taskID]; ok {
			t.Step = step
			t.Logs = append(t.Logs, fmt.Sprintf("[%s] %s", time.Now().Format("15:04:05"), msg))
		}
		s.deployMu.Unlock()
	}
	finish := func(status, errMsg, localTok string) {
		now := time.Now().UTC()
		s.deployMu.Lock()
		if t, ok := s.deployTasks[taskID]; ok {
			t.Status = status
			t.Error = errMsg
			t.LocalToken = localTok
			t.FinishedAt = &now
			if status == "succeeded" {
				t.Step = "done"
				t.Logs = append(t.Logs, fmt.Sprintf("[%s] 部署完成！节点 %s 已就绪。", now.Format("15:04:05"), req.NodeID))
			} else {
				t.Step = "failed"
				t.Logs = append(t.Logs, fmt.Sprintf("[%s] 部署失败: %s", now.Format("15:04:05"), errMsg))
			}
		}
		s.deployMu.Unlock()
	}

	// Register / update node record in Center DB before pushing config so first heartbeat authenticates immediately.
	centerTok := auth.GenerateRandomToken(24)
	localTok := auth.GenerateRandomToken(24)
	name := req.NodeName
	if name == "" {
		name = req.NodeID
	}
	appendLog("register_node", fmt.Sprintf("在中心注册/更新节点 %s (%s)...", req.NodeID, pubAddr))
	if err := s.store.UpsertNode(ctx, protocol.NodeRecord{
		ID:         req.NodeID,
		Name:       name,
		Role:       protocol.RoleAgentA,
		Projects:   req.Projects,
		PublicAddr: pubAddr,
		CreatedAt:  time.Now().UTC(),
	}, centerTok); err != nil {
		finish("failed", "register node in center db: "+err.Error(), "")
		return
	}

	// Clear any stale upgrade marker for this node since we are installing a fresh version directly.
	_ = s.store.DeleteNodeUpgrade(ctx, req.NodeID)

	err := s.deployer.InstallAgentA(ctx, deployer.InstallAgentAParams{
		Req:         req,
		BinaryPath:  s.releaseFilePath(rel.Filename),
		Release:     rel,
		CenterToken: centerTok,
		LocalToken:  localTok,
		Log:         appendLog,
	})
	if err != nil {
		finish("failed", err.Error(), "")
		return
	}

	// Wait briefly for the newly installed Agent A to send its first heartbeat.
	appendLog("wait_online", "等待节点首次心跳上线验证（最多 15s）...")
	deadline := time.Now().Add(15 * time.Second)
	online := false
	for time.Now().Before(deadline) {
		if st, ok := s.hub.GetLiveA(req.NodeID); ok && s.hub.IsOnline(st.LastSeen) {
			online = true
			appendLog("wait_online", fmt.Sprintf("节点已成功上线！版本: %s (%s/%s)", st.Version, st.OS, st.Arch))
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if !online {
		appendLog("wait_online", "服务已启动，尚未收到首次心跳（请检查目标机到中心 "+s.cfg.PublicURL+" 的网络连通性）")
	}

	finish("succeeded", "", localTok)
}

func (s *Server) putDeployTask(t *protocol.DeployTask) {
	s.deployMu.Lock()
	defer s.deployMu.Unlock()
	s.deployTasks[t.ID] = t
	s.deployOrder = append(s.deployOrder, t.ID)
	const maxHistory = 50
	for len(s.deployOrder) > maxHistory {
		old := s.deployOrder[0]
		s.deployOrder = s.deployOrder[1:]
		delete(s.deployTasks, old)
	}
}

func (s *Server) cloneDeployTask(id string) *protocol.DeployTask {
	s.deployMu.RLock()
	defer s.deployMu.RUnlock()
	t, ok := s.deployTasks[id]
	if !ok {
		return nil
	}
	cp := *t
	cp.Logs = append([]string(nil), t.Logs...)
	return &cp
}

func (s *Server) handleAdminListDeployTasks(w http.ResponseWriter, r *http.Request) {
	s.deployMu.RLock()
	out := make([]protocol.DeployTask, 0, len(s.deployOrder))
	for i := len(s.deployOrder) - 1; i >= 0; i-- {
		if t, ok := s.deployTasks[s.deployOrder[i]]; ok {
			cp := *t
			cp.Logs = append([]string(nil), t.Logs...)
			cp.LocalToken = "" // never expose one-time token in history list
			out = append(out, cp)
		}
	}
	s.deployMu.RUnlock()
	protocol.WriteJSON(w, http.StatusOK, out)
}

func (s *Server) handleAdminGetDeployTask(w http.ResponseWriter, r *http.Request) {
	t := s.cloneDeployTask(r.PathValue("id"))
	if t == nil {
		protocol.WriteError(w, http.StatusNotFound, "deploy task not found")
		return
	}
	protocol.WriteJSON(w, http.StatusOK, t)
}

func (s *Server) handleAdminAgentBInstallScript(w http.ResponseWriter, r *http.Request) {
	var req protocol.AgentBScriptReq
	if err := protocol.DecodeJSON(r.Body, &req); err != nil {
		protocol.WriteError(w, http.StatusBadRequest, "invalid json")
		return
	}
	req.NodeID = strings.TrimSpace(req.NodeID)
	if req.NodeID == "" {
		protocol.WriteError(w, http.StatusBadRequest, "node_id is required")
		return
	}
	if s.cfg.PublicURL == "" || s.cfg.CACert == "" {
		protocol.WriteError(w, http.StatusBadRequest, "center config requires public_url and ca_cert")
		return
	}
	node, err := s.store.GetNode(r.Context(), req.NodeID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			protocol.WriteError(w, http.StatusNotFound, "node not found")
			return
		}
		protocol.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if node.Role != protocol.RoleAgentB {
		protocol.WriteError(w, http.StatusBadRequest, "node is not an agent_b node")
		return
	}

	var rel *protocol.ReleaseRecord
	if req.ReleaseID != "" {
		rel, err = s.store.GetRelease(r.Context(), req.ReleaseID)
	} else {
		rel, err = s.store.LatestReleaseFor(r.Context(), protocol.RoleAgentB, "linux", "amd64")
	}
	if err != nil || rel.Role != protocol.RoleAgentB {
		protocol.WriteError(w, http.StatusBadRequest, "no matching agent_b release found: please upload a Linux agent_b binary first")
		return
	}

	caBytes, err := os.ReadFile(s.cfg.CACert)
	if err != nil {
		protocol.WriteError(w, http.StatusInternalServerError, "read ca_cert: "+err.Error())
		return
	}

	rawTok := strings.TrimSpace(req.NodeToken)
	var rotatedTok string
	if req.RotateToken {
		rotatedTok = auth.GenerateRandomToken(24)
		rawTok = rotatedTok
		if err := s.store.UpsertNode(r.Context(), *node, rotatedTok); err != nil {
			protocol.WriteError(w, http.StatusInternalServerError, "rotate node token: "+err.Error())
			return
		}
		s.hub.DisconnectSSE(node.ID)
	}

	script, err := deployer.RenderAgentBInstallScript(s.cfg.PublicURL, caBytes, *node, rawTok, *rel, req)
	if err != nil {
		protocol.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	protocol.WriteJSON(w, http.StatusOK, protocol.AgentBScriptResp{
		NodeID:       node.ID,
		Script:       script,
		RotatedToken: rotatedTok,
	})
}
