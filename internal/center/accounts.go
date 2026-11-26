package center

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"relay-download/internal/auth"
	"relay-download/internal/protocol"
)

type principalCtxKey struct{}

// consolePrincipal identifies the authenticated operator or customer calling the console API.
type consolePrincipal struct {
	Role        string   // protocol.AccountRoleAdmin | protocol.AccountRoleCustomer
	AccountID   string
	AccountName string
	Projects    []string // empty = all projects (only restricts when Role == customer)
	TrustedIP   bool
}

func (p consolePrincipal) IsAdmin() bool {
	return p.Role == protocol.AccountRoleAdmin
}

func (p consolePrincipal) AllowsProject(projectID string) bool {
	if p.IsAdmin() || len(p.Projects) == 0 {
		return true
	}
	return nodeAllowsProject(p.Projects, projectID)
}

func (p consolePrincipal) AllowsAllProjects(projects []string) bool {
	if p.IsAdmin() || len(p.Projects) == 0 {
		return true
	}
	if len(projects) == 0 {
		// A project-scoped customer cannot create or operate wildcard ("all projects") receiver nodes.
		return false
	}
	for _, pid := range projects {
		if !nodeAllowsProject(p.Projects, pid) {
			return false
		}
	}
	return true
}

func (p consolePrincipal) CanAccessNode(n protocol.NodeRecord) bool {
	if p.IsAdmin() {
		return true
	}
	// Customer accounts can NEVER view or control dispatch (agent_a) nodes.
	if n.Role != protocol.RoleAgentB {
		return false
	}
	return p.AllowsAllProjects(n.Projects)
}

func principalFromRequest(r *http.Request) consolePrincipal {
	if p, ok := r.Context().Value(principalCtxKey{}).(consolePrincipal); ok {
		return p
	}
	return consolePrincipal{}
}

func (s *Server) authenticateConsole(r *http.Request) (consolePrincipal, bool) {
	tok := strings.TrimSpace(r.Header.Get(protocol.HeaderAdminToken))
	if tok == "" {
		tok = auth.ExtractBearer(r.Header.Get("Authorization"))
	}
	// Explicit token header always takes precedence so an operator on a trusted IP can also
	// test customer tokens or verify token revocation from the same workstation.
	if tok != "" {
		if auth.EqualConstantTime(tok, s.cfg.AdminToken) {
			return consolePrincipal{
				Role:        protocol.AccountRoleAdmin,
				AccountName: "管理员",
				TrustedIP:   s.isTrustedAdminRequest(r),
			}, true
		}
		if acc, err := s.store.AuthenticateAccount(r.Context(), tok); err == nil && acc != nil {
			return consolePrincipal{
				Role:        protocol.AccountRoleCustomer,
				AccountID:   acc.ID,
				AccountName: acc.Name,
				Projects:    append([]string(nil), acc.Projects...),
				TrustedIP:   false,
			}, true
		}
		return consolePrincipal{}, false
	}
	if s.isTrustedAdminRequest(r) {
		return consolePrincipal{
			Role:        protocol.AccountRoleAdmin,
			AccountName: "管理员",
			TrustedIP:   true,
		}, true
	}
	return consolePrincipal{}, false
}

// requireConsole allows both super-admin and enabled customer accounts, injecting consolePrincipal into context.
func (s *Server) requireConsole(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := checkAdminCSRF(r); err != nil {
			protocol.WriteError(w, http.StatusForbidden, err.Error())
			return
		}
		p, ok := s.authenticateConsole(r)
		if !ok {
			protocol.WriteError(w, http.StatusUnauthorized, "invalid access token")
			return
		}
		ctx := context.WithValue(r.Context(), principalCtxKey{}, p)
		next(w, r.WithContext(ctx))
	}
}

// requireSuperAdmin strictly permits only the super-admin token (or trusted admin IP with no customer token).
// Customer accounts always receive 403 Forbidden.
func (s *Server) requireSuperAdmin(next http.HandlerFunc) http.HandlerFunc {
	return s.requireConsole(func(w http.ResponseWriter, r *http.Request) {
		p := principalFromRequest(r)
		if !p.IsAdmin() {
			protocol.WriteError(w, http.StatusForbidden, "admin privileges required")
			return
		}
		next(w, r)
	})
}

type createAccountReq struct {
	ID       string   `json:"id,omitempty"`
	Name     string   `json:"name"`
	Projects []string `json:"projects,omitempty"`
	Token    string   `json:"token,omitempty"`
}

type updateAccountReq struct {
	Name     string    `json:"name,omitempty"`
	Projects *[]string `json:"projects,omitempty"`
	Enabled  *bool     `json:"enabled,omitempty"`
}

func (s *Server) handleAdminListAccounts(w http.ResponseWriter, r *http.Request) {
	list, err := s.store.ListAccounts(r.Context())
	if err != nil {
		protocol.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	protocol.WriteJSON(w, http.StatusOK, list)
}

func (s *Server) handleAdminCreateAccount(w http.ResponseWriter, r *http.Request) {
	var req createAccountReq
	if err := protocol.DecodeJSON(r.Body, &req); err != nil {
		protocol.WriteError(w, http.StatusBadRequest, "invalid json")
		return
	}
	req.ID = strings.TrimSpace(req.ID)
	if req.ID == "" {
		req.ID = "cust-" + strings.ReplaceAll(uuid.NewString(), "-", "")[:8]
	}
	if !validIDRe.MatchString(req.ID) {
		protocol.WriteError(w, http.StatusBadRequest, "invalid account id: only [A-Za-z0-9._-] (1-64 chars) allowed")
		return
	}
	req.Name = sanitizeSingleLine(req.Name, 128)
	if req.Name == "" {
		req.Name = req.ID
	}
	cleanProjects, err := cleanProjectIDList(req.Projects)
	if err != nil {
		protocol.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	rawToken := strings.TrimSpace(req.Token)
	if rawToken == "" {
		rawToken = "rcust_" + auth.GenerateRandomToken(24)
	} else if len(rawToken) < 16 {
		protocol.WriteError(w, http.StatusBadRequest, "custom token must be at least 16 characters")
		return
	}
	if auth.EqualConstantTime(rawToken, s.cfg.AdminToken) {
		protocol.WriteError(w, http.StatusBadRequest, "customer token cannot equal admin token")
		return
	}

	rec := protocol.AccountRecord{
		ID:        req.ID,
		Name:      req.Name,
		Role:      protocol.AccountRoleCustomer,
		Projects:  cleanProjects,
		Enabled:   true,
		CreatedAt: time.Now().UTC(),
	}
	if err := s.store.CreateAccount(r.Context(), rec, rawToken); err != nil {
		if errors.Is(err, ErrConflict) {
			protocol.WriteError(w, http.StatusConflict, "account id already exists")
			return
		}
		protocol.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	protocol.WriteJSON(w, http.StatusOK, map[string]any{
		"account": rec,
		"token":   rawToken,
	})
}

func (s *Server) handleAdminUpdateAccount(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("id"))
	existing, err := s.store.GetAccount(r.Context(), id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			protocol.WriteError(w, http.StatusNotFound, "account not found")
			return
		}
		protocol.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	var req updateAccountReq
	if err := protocol.DecodeJSON(r.Body, &req); err != nil {
		protocol.WriteError(w, http.StatusBadRequest, "invalid json")
		return
	}
	rec := *existing
	if name := sanitizeSingleLine(req.Name, 128); name != "" {
		rec.Name = name
	}
	if req.Projects != nil {
		cleanProjects, err := cleanProjectIDList(*req.Projects)
		if err != nil {
			protocol.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		rec.Projects = cleanProjects
	}
	if req.Enabled != nil {
		rec.Enabled = *req.Enabled
	}
	if err := s.store.UpdateAccount(r.Context(), rec); err != nil {
		protocol.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	protocol.WriteJSON(w, http.StatusOK, rec)
}

func (s *Server) handleAdminRotateAccountToken(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("id"))
	newToken := "rcust_" + auth.GenerateRandomToken(24)
	rec, err := s.store.RotateAccountToken(r.Context(), id, newToken)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			protocol.WriteError(w, http.StatusNotFound, "account not found")
			return
		}
		protocol.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	protocol.WriteJSON(w, http.StatusOK, map[string]any{
		"account": rec,
		"token":   newToken,
	})
}

func (s *Server) handleAdminDeleteAccount(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("id"))
	if err := s.store.DeleteAccount(r.Context(), id); err != nil {
		if errors.Is(err, ErrNotFound) {
			protocol.WriteError(w, http.StatusNotFound, "account not found")
			return
		}
		protocol.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
