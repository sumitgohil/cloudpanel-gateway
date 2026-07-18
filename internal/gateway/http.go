package gateway

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type APIServer struct {
	Config   Config
	State    *State
	Logger   *slog.Logger
	requests atomic.Uint64
	denied   atomic.Uint64
	mcp      http.Handler
	uploadMu sync.Mutex
}
type actionBody struct {
	Args map[string]string `json:"args"`
}
type actionResult struct {
	Action    string `json:"action"`
	OK        bool   `json:"ok"`
	Output    string `json:"output,omitempty"`
	Error     string `json:"error,omitempty"`
	ExitCode  int    `json:"exit_code"`
	RequestID string `json:"request_id"`
}

type mcpLogSourcesInput struct {
	Domain string `json:"domain" jsonschema:"The CloudPanel site domain, for example wp1.example.com"`
}

type mcpLogQueryInput struct {
	Domain     string   `json:"domain" jsonschema:"The CloudPanel site domain"`
	Sources    []string `json:"sources,omitempty" jsonschema:"Source IDs from cloudpanel_site_logs_list_sources; defaults to nginx and PHP logs"`
	AppLogPath string   `json:"app_log_path,omitempty" jsonschema:"Optional log file or directory path relative to the site's document root"`
	From       string   `json:"from,omitempty" jsonschema:"Inclusive RFC3339 UTC timestamp; defaults to 24 hours ago"`
	To         string   `json:"to,omitempty" jsonschema:"Inclusive RFC3339 UTC timestamp; defaults to now"`
	Contains   string   `json:"contains,omitempty" jsonschema:"Optional case-insensitive text filter"`
	Statuses   []int    `json:"statuses,omitempty" jsonschema:"Optional HTTP status-code filters"`
	MaxLines   int      `json:"max_lines,omitempty" jsonschema:"Maximum returned lines, 1 through 1000; default 200"`
	Raw        bool     `json:"raw,omitempty" jsonschema:"Return unredacted log lines; requires an admin token"`
	Symptom    string   `json:"symptom,omitempty" jsonschema:"Optional user symptom or observed context for the AI client"`
}

type mcpSiteInput struct {
	Domain string `json:"domain"`
}
type mcpRootInput struct {
	Domain          string `json:"domain"`
	RootDirectory   string `json:"root_directory"`
	IfMatchRevision string `json:"if_match_revision"`
	Confirm         bool   `json:"confirm"`
}
type mcpPasswordInput struct {
	Domain          string `json:"domain"`
	IfMatchRevision string `json:"if_match_revision"`
	Confirm         bool   `json:"confirm"`
}
type mcpPHPUpdateInput struct {
	Domain          string            `json:"domain"`
	IfMatchRevision string            `json:"if_match_revision"`
	Values          map[string]string `json:"values"`
}
type mcpPageSpeedInput struct {
	Domain          string   `json:"domain"`
	IfMatchRevision string   `json:"if_match_revision"`
	Enabled         bool     `json:"enabled"`
	Preset          string   `json:"preset"`
	EnableFilters   []string `json:"enable_filters,omitempty"`
	DisableFilters  []string `json:"disable_filters,omitempty"`
}
type mcpDeployInput struct {
	Domain     string `json:"domain"`
	ArtifactID string `json:"artifact_id"`
	TargetDir  string `json:"target_dir"`
	Replace    bool   `json:"replace"`
	Confirm    bool   `json:"confirm"`
}
type mcpRootDeployInput struct {
	Domain     string `json:"domain"`
	ArtifactID string `json:"artifact_id"`
	Replace    bool   `json:"replace"`
	Confirm    bool   `json:"confirm"`
}
type mcpBackupCreateInput struct {
	Domain     string `json:"domain"`
	Components string `json:"components"`
}
type mcpBackupRestoreInput struct {
	Domain     string `json:"domain"`
	BackupID   string `json:"backup_id"`
	Components string `json:"components"`
	Confirm    bool   `json:"confirm"`
}
type mcpArtifactBeginInput struct {
	TotalChunks int `json:"total_chunks"`
}
type mcpArtifactChunkInput struct {
	UploadID   string `json:"upload_id"`
	Index      int    `json:"index"`
	DataBase64 string `json:"data_base64"`
}
type mcpArtifactCompleteInput struct {
	UploadID string `json:"upload_id"`
}
type mcpCronInput struct {
	Domain          string   `json:"domain"`
	JobID           int64    `json:"job_id,omitempty"`
	Minute          string   `json:"minute,omitempty"`
	Hour            string   `json:"hour,omitempty"`
	Day             string   `json:"day,omitempty"`
	Month           string   `json:"month,omitempty"`
	Weekday         string   `json:"weekday,omitempty"`
	Runner          string   `json:"runner,omitempty"`
	Target          string   `json:"target,omitempty"`
	Args            []string `json:"args,omitempty"`
	Method          string   `json:"method,omitempty"`
	URL             string   `json:"url,omitempty"`
	RawCommand      string   `json:"raw_command,omitempty"`
	IfMatchRevision string   `json:"if_match_revision,omitempty"`
	Confirm         bool     `json:"confirm,omitempty"`
}
type mcpNodeInput struct {
	Domain          string   `json:"domain"`
	ArtifactID      string   `json:"artifact_id,omitempty"`
	Framework       string   `json:"framework,omitempty"`
	Entrypoint      string   `json:"entrypoint,omitempty"`
	Args            []string `json:"args,omitempty"`
	NodeVersion     string   `json:"node_version,omitempty"`
	AppPort         int      `json:"app_port,omitempty"`
	HealthPath      string   `json:"health_path,omitempty"`
	IfMatchRevision string   `json:"if_match_revision,omitempty"`
	Confirm         bool     `json:"confirm,omitempty"`
}
type mcpBuildInput struct {
	Domain     string `json:"domain"`
	ArtifactID string `json:"artifact_id"`
	Framework  string `json:"framework"`
	OutputDir  string `json:"output_dir,omitempty"`
}
type tokenContextKey struct{}

func NewAPIServer(c Config, s *State, logger *slog.Logger) *APIServer {
	a := &APIServer{Config: c, State: s, Logger: logger}
	a.mcp = mcp.NewStreamableHTTPHandler(func(r *http.Request) *mcp.Server {
		t, _ := r.Context().Value(tokenContextKey{}).(*Token)
		if t == nil {
			return nil
		}
		return a.newMCP(t)
	}, &mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true, Logger: logger, DisableLocalhostProtection: true})
	return a
}
func (a *APIServer) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", a.health)
	mux.HandleFunc("/readyz", a.ready)
	mux.HandleFunc("/openapi.json", a.auth(a.openapi, "docs:read"))
	mux.HandleFunc("/docs", a.auth(a.docs, "docs:read"))
	mux.HandleFunc("/metrics", a.auth(a.metrics, "metrics:read"))
	mux.Handle("/mcp", a.mcpAuth(a.mcp))
	mux.HandleFunc("/v1/artifacts", a.auth(a.artifacts, "artifacts:write"))
	mux.HandleFunc("/v1/artifacts/uploads/", a.auth(a.artifactUploads, "artifacts:write"))
	mux.HandleFunc("/v1/projects/inspect", a.auth(a.projectInspect, "artifacts:write"))
	mux.HandleFunc("/v1/sites", a.auth(a.sites, "sites:write"))
	mux.HandleFunc("/v1/sites/", a.auth(a.siteLogs, ""))
	mux.HandleFunc("/v1/actions/", a.auth(a.action, ""))
	return a.limit(a.requestID(mux))
}
func (a *APIServer) limit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Artifact uploads are individually constrained to 100 MiB. Other API
		// requests remain bounded well below this by their JSON decoding rules.
		r.Body = http.MaxBytesReader(w, r.Body, 101<<20)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}
func (a *APIServer) requestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.requests.Add(1)
		id := r.Header.Get("X-Request-ID")
		if len(id) < 8 || len(id) > 100 {
			id, _ = newID("req_", 12)
		}
		w.Header().Set("X-Request-ID", id)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), requestIDKey{}, id)))
	})
}

type requestIDKey struct{}

func requestID(r *http.Request) string { v, _ := r.Context().Value(requestIDKey{}).(string); return v }
func (a *APIServer) token(r *http.Request) (*Token, error) {
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, "Bearer ") {
		return nil, fmt.Errorf("missing bearer token")
	}
	return a.State.Authenticate(strings.TrimSpace(strings.TrimPrefix(h, "Bearer ")))
}
func (a *APIServer) auth(next http.HandlerFunc, scope string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		t, e := a.token(r)
		if e != nil || (!HasScope(t, scope) && scope != "") {
			a.denied.Add(1)
			jsonError(w, http.StatusUnauthorized, "unauthorized", requestID(r))
			return
		}
		if scope != "" && !HasScope(t, scope) {
			a.denied.Add(1)
			jsonError(w, http.StatusForbidden, "insufficient scope", requestID(r))
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), tokenContextKey{}, t)))
	}
}
func (a *APIServer) mcpAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !a.validMCPOrigin(r) {
			a.denied.Add(1)
			jsonError(w, http.StatusForbidden, "invalid origin", requestID(r))
			return
		}
		t, e := a.token(r)
		if e != nil {
			a.denied.Add(1)
			jsonError(w, http.StatusUnauthorized, "unauthorized", requestID(r))
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), tokenContextKey{}, t)))
	})
}
func (a *APIServer) validMCPOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	o, e := http.NewRequest(http.MethodGet, origin, nil)
	if e != nil {
		return false
	}
	host := strings.ToLower(o.URL.Hostname())
	if host == "localhost" || host == "127.0.0.1" {
		return true
	}
	for _, v := range a.Config.AllowedHosts {
		if strings.EqualFold(host, v) {
			return true
		}
	}
	if _, _, err := a.State.Domain(host); err == nil {
		return true
	}
	return false
}
func (a *APIServer) health(w http.ResponseWriter, r *http.Request) {
	jsonResponse(w, 200, map[string]any{"status": "ok", "service": "cloudpanel-gateway"})
}
func (a *APIServer) ready(w http.ResponseWriter, r *http.Request) {
	if _, e := a.State.DB.Exec("SELECT 1"); e != nil {
		jsonError(w, 503, "state unavailable", requestID(r))
		return
	}
	jsonResponse(w, 200, map[string]string{"status": "ready"})
}
func (a *APIServer) action(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(405)
		return
	}
	name := strings.TrimPrefix(r.URL.Path, "/v1/actions/")
	var in actionBody
	if e := json.NewDecoder(r.Body).Decode(&in); e != nil {
		jsonError(w, 400, "invalid JSON", requestID(r))
		return
	}
	a.executeAction(w, r, name, in.Args)
}
func (a *APIServer) executeAction(w http.ResponseWriter, r *http.Request, name string, args map[string]string) {
	spec, e := ValidateAction(name, args, a.Config.ArtifactDir)
	if e != nil {
		jsonError(w, 400, e.Error(), requestID(r))
		return
	}
	t := r.Context().Value(tokenContextKey{}).(*Token)
	if !HasScope(t, spec.Scope) {
		jsonError(w, 403, "insufficient scope", requestID(r))
		return
	}
	start := time.Now()
	res, e := CallHelper(r.Context(), a.Config, name, args)
	out := actionResult{Action: name, OK: e == nil && res.OK, Output: res.Stdout, Error: res.Error, ExitCode: res.ExitCode, RequestID: requestID(r)}
	outcome := "ok"
	if !out.OK {
		outcome = "error"
	}
	a.State.Audit(requestID(r), t.ID, name, outcome, out.Error, time.Since(start))
	if e != nil {
		jsonError(w, 502, "helper unavailable", requestID(r))
		return
	}
	if !res.OK {
		jsonResponse(w, 400, out)
		return
	}
	jsonResponse(w, 200, out)
}
func (a *APIServer) sites(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(405)
		return
	}
	var in struct {
		Type             string `json:"type"`
		Domain           string `json:"domain"`
		SiteUser         string `json:"site_user"`
		SiteUserPassword string `json:"site_user_password"`
		Version          string `json:"version"`
		AppPort          string `json:"app_port"`
		VHostTemplate    string `json:"vhost_template"`
		ReverseProxyURL  string `json:"reverse_proxy_url"`
	}
	if json.NewDecoder(r.Body).Decode(&in) != nil {
		jsonError(w, 400, "invalid JSON", requestID(r))
		return
	}
	actions := map[string]string{"static": "site.create_static", "nodejs": "site.create_nodejs", "php": "site.create_php", "python": "site.create_python", "reverse_proxy": "site.create_reverse_proxy"}
	name, ok := actions[in.Type]
	if !ok {
		jsonError(w, 400, "unsupported site type", requestID(r))
		return
	}
	args := map[string]string{"domainName": in.Domain, "siteUser": in.SiteUser, "siteUserPassword": in.SiteUserPassword}
	switch in.Type {
	case "nodejs":
		args["nodejsVersion"] = in.Version
		args["appPort"] = in.AppPort
	case "php":
		args["phpVersion"] = in.Version
		args["vhostTemplate"] = in.VHostTemplate
	case "python":
		args["pythonVersion"] = in.Version
		args["appPort"] = in.AppPort
	case "reverse_proxy":
		args["reverseProxyUrl"] = in.ReverseProxyURL
	}
	a.executeAction(w, r, name, args)
}
func (a *APIServer) artifacts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(405)
		return
	}
	if e := os.MkdirAll(a.Config.ArtifactDir, 0750); e != nil {
		jsonError(w, 500, "artifact storage unavailable", requestID(r))
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxZIPCompressed)
	id, e := newID("artifact_", 18)
	if e != nil {
		jsonError(w, 500, "randomness unavailable", requestID(r))
		return
	}
	path := filepath.Join(a.Config.ArtifactDir, id)
	f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		jsonError(w, 500, "artifact create failed", requestID(r))
		return
	}
	h := sha256.New()
	n, e := io.Copy(io.MultiWriter(f, h), r.Body)
	closeErr := f.Close()
	if e != nil || closeErr != nil {
		_ = os.Remove(path)
		jsonError(w, 400, "artifact upload failed", requestID(r))
		return
	}
	if n < 4 {
		_ = os.Remove(path)
		jsonError(w, 400, "artifact must be a ZIP archive", requestID(r))
		return
	}
	probe, probeErr := os.Open(path)
	if probeErr != nil {
		jsonError(w, 500, "artifact validation failed", requestID(r))
		return
	}
	magic := make([]byte, 4)
	_, probeErr = io.ReadFull(probe, magic)
	_ = probe.Close()
	if probeErr != nil || string(magic[:2]) != "PK" {
		_ = os.Remove(path)
		jsonError(w, 400, "artifact must be a ZIP archive", requestID(r))
		return
	}
	if e = validateArtifactZIP(path); e != nil {
		_ = os.Remove(path)
		jsonError(w, 400, e.Error(), requestID(r))
		return
	}
	t, _ := r.Context().Value(tokenContextKey{}).(*Token)
	now := time.Now().UTC()
	artifact := Artifact{ID: id, Path: path, SHA256: hex.EncodeToString(h.Sum(nil)), Size: n, OwnerTokenID: t.ID, CreatedAt: now, ExpiresAt: now.Add(artifactTTL)}
	if e = a.State.PutArtifact(artifact); e != nil {
		_ = os.Remove(path)
		jsonError(w, 500, "artifact metadata create failed", requestID(r))
		return
	}
	_ = a.State.CleanupArtifacts(now)
	jsonResponse(w, 201, map[string]any{"id": id, "sha256": artifact.SHA256, "size": n, "expires_at": artifact.ExpiresAt})
}

func (a *APIServer) beginArtifactUpload(t *Token, totalChunks int) (ArtifactUpload, error) {
	if totalChunks < 1 || totalChunks > maxArtifactChunks {
		return ArtifactUpload{}, fmt.Errorf("total_chunks must be between 1 and %d", maxArtifactChunks)
	}
	a.uploadMu.Lock()
	defer a.uploadMu.Unlock()
	if err := os.MkdirAll(a.Config.ArtifactDir, 0750); err != nil {
		return ArtifactUpload{}, err
	}
	_ = a.State.CleanupArtifacts(time.Now())
	id, err := newID("upload_", 18)
	if err != nil {
		return ArtifactUpload{}, err
	}
	path := filepath.Join(a.Config.ArtifactDir, "."+id+".part")
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return ArtifactUpload{}, err
	}
	if err = f.Close(); err != nil {
		return ArtifactUpload{}, err
	}
	now := time.Now().UTC()
	u := ArtifactUpload{ID: id, Path: path, OwnerTokenID: t.ID, TotalChunks: totalChunks, CreatedAt: now, ExpiresAt: now.Add(artifactTTL)}
	if err = a.State.PutArtifactUpload(u); err != nil {
		_ = os.Remove(path)
		return ArtifactUpload{}, err
	}
	return u, nil
}
func (a *APIServer) appendArtifactChunk(t *Token, id string, index int, data []byte) (ArtifactUpload, error) {
	if len(data) == 0 || len(data) > maxArtifactChunk {
		return ArtifactUpload{}, fmt.Errorf("chunk must be 1 through %d bytes", maxArtifactChunk)
	}
	a.uploadMu.Lock()
	defer a.uploadMu.Unlock()
	u, err := a.State.ArtifactUpload(id)
	if err != nil {
		return ArtifactUpload{}, errors.New("upload not found")
	}
	if u.OwnerTokenID != t.ID {
		return ArtifactUpload{}, errors.New("upload is not owned by this token")
	}
	if time.Now().After(u.ExpiresAt) {
		return ArtifactUpload{}, errors.New("upload expired")
	}
	if index != u.NextChunk || index >= u.TotalChunks {
		return ArtifactUpload{}, errors.New("unexpected upload chunk index")
	}
	st, err := os.Stat(u.Path)
	if err != nil || st.Size() != u.Size {
		return ArtifactUpload{}, errors.New("upload state is inconsistent")
	}
	if u.Size+int64(len(data)) > maxZIPCompressed {
		return ArtifactUpload{}, errors.New("artifact exceeds 100 MiB compressed limit")
	}
	f, err := os.OpenFile(u.Path, os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return ArtifactUpload{}, err
	}
	_, err = f.Write(data)
	closeErr := f.Close()
	if err != nil {
		return ArtifactUpload{}, err
	}
	if closeErr != nil {
		return ArtifactUpload{}, closeErr
	}
	u.Size += int64(len(data))
	u.NextChunk++
	if err = a.State.AdvanceArtifactUpload(u.ID, u.Size, u.NextChunk); err != nil {
		return ArtifactUpload{}, err
	}
	return u, nil
}
func (a *APIServer) completeArtifactUpload(t *Token, id string) (Artifact, error) {
	a.uploadMu.Lock()
	defer a.uploadMu.Unlock()
	u, err := a.State.ArtifactUpload(id)
	if err != nil {
		return Artifact{}, errors.New("upload not found")
	}
	if u.OwnerTokenID != t.ID {
		return Artifact{}, errors.New("upload is not owned by this token")
	}
	if time.Now().After(u.ExpiresAt) || u.NextChunk != u.TotalChunks || u.Size < 4 {
		return Artifact{}, errors.New("upload is incomplete or expired")
	}
	if err = validateArtifactZIP(u.Path); err != nil {
		return Artifact{}, err
	}
	f, err := os.Open(u.Path)
	if err != nil {
		return Artifact{}, err
	}
	h := sha256.New()
	_, err = io.Copy(h, f)
	closeErr := f.Close()
	if err != nil {
		return Artifact{}, err
	}
	if closeErr != nil {
		return Artifact{}, closeErr
	}
	artifactID, err := newID("artifact_", 18)
	if err != nil {
		return Artifact{}, err
	}
	path := filepath.Join(a.Config.ArtifactDir, artifactID)
	if err = os.Rename(u.Path, path); err != nil {
		return Artifact{}, err
	}
	now := time.Now().UTC()
	artifact := Artifact{ID: artifactID, Path: path, SHA256: hex.EncodeToString(h.Sum(nil)), Size: u.Size, OwnerTokenID: t.ID, CreatedAt: now, ExpiresAt: now.Add(artifactTTL)}
	if err = a.State.PutArtifact(artifact); err != nil {
		_ = os.Rename(path, u.Path)
		return Artifact{}, err
	}
	if err = a.State.DeleteArtifactUpload(u.ID); err != nil {
		return Artifact{}, err
	}
	return artifact, nil
}
func (a *APIServer) artifactUploads(w http.ResponseWriter, r *http.Request) {
	t, _ := r.Context().Value(tokenContextKey{}).(*Token)
	parts := strings.Split(strings.Trim(strings.TrimPrefix(r.URL.Path, "/v1/artifacts/uploads/"), "/"), "/")
	if len(parts) == 1 && parts[0] == "begin" && r.Method == http.MethodPost {
		var in struct {
			TotalChunks int `json:"total_chunks"`
		}
		if json.NewDecoder(r.Body).Decode(&in) != nil {
			jsonError(w, 400, "invalid JSON upload request", requestID(r))
			return
		}
		out, e := a.beginArtifactUpload(t, in.TotalChunks)
		if e != nil {
			jsonError(w, 400, e.Error(), requestID(r))
			return
		}
		jsonResponse(w, 201, map[string]any{"upload_id": out.ID, "max_chunk_bytes": maxArtifactChunk, "expires_at": out.ExpiresAt})
		return
	}
	if len(parts) == 2 && r.Method == http.MethodPost {
		if parts[1] == "chunk" {
			var in struct {
				Index      int    `json:"index"`
				DataBase64 string `json:"data_base64"`
			}
			d := json.NewDecoder(r.Body)
			d.DisallowUnknownFields()
			if d.Decode(&in) != nil || len(in.DataBase64) > base64.StdEncoding.EncodedLen(maxArtifactChunk) {
				jsonError(w, 400, "invalid upload chunk", requestID(r))
				return
			}
			data, e := base64.StdEncoding.DecodeString(in.DataBase64)
			if e != nil {
				jsonError(w, 400, "invalid base64 chunk", requestID(r))
				return
			}
			out, e := a.appendArtifactChunk(t, parts[0], in.Index, data)
			if e != nil {
				jsonError(w, 400, e.Error(), requestID(r))
				return
			}
			jsonResponse(w, 200, map[string]any{"upload_id": out.ID, "next_chunk": out.NextChunk, "size": out.Size})
			return
		}
		if parts[1] == "complete" {
			out, e := a.completeArtifactUpload(t, parts[0])
			if e != nil {
				jsonError(w, 400, e.Error(), requestID(r))
				return
			}
			jsonResponse(w, 201, map[string]any{"id": out.ID, "sha256": out.SHA256, "size": out.Size, "expires_at": out.ExpiresAt})
			return
		}
	}
	jsonError(w, 404, "artifact upload endpoint not found", requestID(r))
}

func (a *APIServer) projectInspect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var in struct {
		ArtifactID string `json:"artifact_id"`
	}
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if d.Decode(&in) != nil {
		jsonError(w, http.StatusBadRequest, "invalid JSON project inspection request", requestID(r))
		return
	}
	t, _ := r.Context().Value(tokenContextKey{}).(*Token)
	var out ProjectInspection
	start := time.Now()
	err := CallTypedHelper(r.Context(), a.Config, HelperRequest{Node: &NodeRequest{Operation: nodeInspect, ArtifactID: in.ArtifactID, OwnerTokenID: t.ID, Domain: "project.invalid"}}, &out)
	a.auditMCP(t, "project.inspect_artifact", start, err)
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error(), requestID(r))
		return
	}
	jsonResponse(w, http.StatusOK, out)
}

func (a *APIServer) siteNode(w http.ResponseWriter, r *http.Request, parts []string) {
	if len(parts) < 2 || ValidateDomain(parts[0]) != nil {
		jsonError(w, http.StatusNotFound, "Node.js endpoint not found", requestID(r))
		return
	}
	domain := parts[0]
	t, _ := r.Context().Value(tokenContextKey{}).(*Token)
	operation, scope := "", ""
	if parts[1] == "builds" && len(parts) == 2 && r.Method == http.MethodPost {
		operation, scope = "build", "node:build"
	} else if parts[1] == "node" {
		switch {
		case len(parts) == 2 && r.Method == http.MethodGet:
			operation, scope = nodeGetSettings, "node:read"
		case len(parts) == 2 && r.Method == http.MethodPatch:
			operation, scope = nodeUpdate, "node:write"
		case len(parts) == 3 && parts[2] == "status" && r.Method == http.MethodGet:
			operation, scope = nodeStatus, "node:read"
		case len(parts) == 3 && parts[2] == "restart" && r.Method == http.MethodPost:
			operation, scope = nodeRestart, "node:write"
		case len(parts) == 3 && parts[2] == "releases" && r.Method == http.MethodGet:
			operation, scope = nodeList, "node:read"
		case len(parts) == 3 && parts[2] == "releases" && r.Method == http.MethodPost:
			operation, scope = nodeDeploy, "node:deploy"
		case len(parts) == 3 && parts[2] == "rollback" && r.Method == http.MethodPost:
			operation, scope = nodeRollback, "node:deploy"
		}
	}
	if operation == "" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if t == nil || !HasScope(t, scope) {
		a.denied.Add(1)
		jsonError(w, http.StatusForbidden, "insufficient scope", requestID(r))
		return
	}
	start := time.Now()
	var out any
	var err error
	if operation == "build" {
		var in mcpBuildInput
		d := json.NewDecoder(r.Body)
		d.DisallowUnknownFields()
		if d.Decode(&in) != nil {
			jsonError(w, 400, "invalid JSON build request", requestID(r))
			return
		}
		value := BuildResult{}
		err = CallTypedHelper(r.Context(), a.Config, HelperRequest{Build: &BuildRequest{Domain: domain, ArtifactID: in.ArtifactID, OwnerTokenID: t.ID, Framework: in.Framework, OutputDir: in.OutputDir}}, &value)
		out = value
	} else {
		in := mcpNodeInput{Domain: domain}
		if r.Method != http.MethodGet {
			d := json.NewDecoder(r.Body)
			d.DisallowUnknownFields()
			if d.Decode(&in) != nil {
				jsonError(w, 400, "invalid JSON Node.js request", requestID(r))
				return
			}
			in.Domain = domain
		}
		value := any(nil)
		switch operation {
		case nodeGetSettings:
			value = &NodeSettings{}
		case nodeStatus:
			value = &NodeStatus{}
		case nodeList:
			value = &NodeReleaseList{}
		default:
			value = &NodeStatus{}
		}
		err = CallTypedHelper(r.Context(), a.Config, HelperRequest{Node: &NodeRequest{Operation: operation, Domain: domain, ArtifactID: in.ArtifactID, OwnerTokenID: t.ID, Framework: in.Framework, Entrypoint: in.Entrypoint, Args: in.Args, NodeVersion: in.NodeVersion, AppPort: in.AppPort, HealthPath: in.HealthPath, IfMatchRevision: in.IfMatchRevision, Confirm: in.Confirm}}, value)
		out = value
	}
	a.auditMCP(t, "node."+operation, start, err)
	if err != nil {
		status := http.StatusBadRequest
		if strings.Contains(err.Error(), "revision conflict") {
			status = http.StatusConflict
		}
		jsonError(w, status, err.Error(), requestID(r))
		return
	}
	jsonResponse(w, http.StatusOK, out)
}

func (a *APIServer) siteStatic(w http.ResponseWriter, r *http.Request, parts []string) {
	if len(parts) == 3 && parts[2] == "deploy" && r.Method == http.MethodPost && ValidateDomain(parts[0]) == nil {
		t, _ := r.Context().Value(tokenContextKey{}).(*Token)
		if t == nil || !HasScope(t, "files:write") {
			a.denied.Add(1)
			jsonError(w, http.StatusForbidden, "insufficient scope", requestID(r))
			return
		}
		var in DeployRequest
		d := json.NewDecoder(r.Body)
		d.DisallowUnknownFields()
		if d.Decode(&in) != nil {
			jsonError(w, 400, "invalid JSON static deployment request", requestID(r))
			return
		}
		in.Domain, in.OwnerTokenID, in.Root, in.Static = parts[0], t.ID, true, true
		out := DeploymentResult{}
		start := time.Now()
		err := CallTypedHelper(r.Context(), a.Config, HelperRequest{Deploy: &in}, &out)
		a.auditMCP(t, "static.deploy_release", start, err)
		if err != nil {
			jsonError(w, 400, err.Error(), requestID(r))
			return
		}
		jsonResponse(w, http.StatusOK, out)
		return
	}
	if len(parts) != 2 || ValidateDomain(parts[0]) != nil {
		jsonError(w, http.StatusNotFound, "static endpoint not found", requestID(r))
		return
	}
	operation, scope := "", ""
	if r.Method == http.MethodGet {
		operation, scope = staticGetRouting, "sites:read"
	} else if r.Method == http.MethodPatch {
		operation, scope = staticUpdateRouting, "sites:write"
	} else {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	t, _ := r.Context().Value(tokenContextKey{}).(*Token)
	if t == nil || !HasScope(t, scope) {
		a.denied.Add(1)
		jsonError(w, http.StatusForbidden, "insufficient scope", requestID(r))
		return
	}
	req := StaticRequest{Operation: operation, Domain: parts[0]}
	if r.Method == http.MethodPatch {
		d := json.NewDecoder(r.Body)
		d.DisallowUnknownFields()
		if d.Decode(&req) != nil {
			jsonError(w, http.StatusBadRequest, "invalid JSON static settings request", requestID(r))
			return
		}
		req.Operation, req.Domain = operation, parts[0]
	}
	start := time.Now()
	out := StaticSettings{}
	err := CallTypedHelper(r.Context(), a.Config, HelperRequest{Static: &req}, &out)
	a.auditMCP(t, "static."+operation, start, err)
	if err != nil {
		status := http.StatusBadRequest
		if strings.Contains(err.Error(), "revision conflict") {
			status = http.StatusConflict
		}
		jsonError(w, status, err.Error(), requestID(r))
		return
	}
	jsonResponse(w, http.StatusOK, out)
}

func (a *APIServer) siteLogs(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/v1/sites/"), "/")
	if len(parts) >= 2 && (parts[1] == "tls" || parts[1] == "deployments" || parts[1] == "backups") {
		a.siteOperations(w, r, parts)
		return
	}
	if len(parts) >= 2 && parts[1] == "cron-jobs" {
		a.siteCron(w, r, parts)
		return
	}
	if len(parts) >= 2 && (parts[1] == "node" || parts[1] == "builds") {
		a.siteNode(w, r, parts)
		return
	}
	if len(parts) >= 2 && parts[1] == "static" {
		a.siteStatic(w, r, parts)
		return
	}
	if len(parts) >= 2 && parts[1] != "logs" {
		a.siteSettings(w, r, parts)
		return
	}
	t, _ := r.Context().Value(tokenContextKey{}).(*Token)
	if t == nil || !HasScope(t, "logs:read") {
		a.denied.Add(1)
		jsonError(w, http.StatusForbidden, "insufficient scope", requestID(r))
		return
	}
	if len(parts) != 3 || parts[1] != "logs" || ValidateDomain(parts[0]) != nil {
		jsonError(w, http.StatusNotFound, "log endpoint not found", requestID(r))
		return
	}
	domain, operation := parts[0], parts[2]
	switch operation {
	case "sources":
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		start := time.Now()
		result, err := CallLogSourcesHelper(r.Context(), a.Config, domain, "")
		a.auditLogRequest(r, t, "logs.list_sources", "", 0, 0, start, err)
		if err != nil {
			jsonError(w, http.StatusBadRequest, err.Error(), requestID(r))
			return
		}
		jsonResponse(w, http.StatusOK, result)
	case "query", "diagnose":
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		var input mcpLogQueryInput
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&input); err != nil {
			jsonError(w, http.StatusBadRequest, "invalid JSON log query", requestID(r))
			return
		}
		if input.Raw && !HasScope(t, "admin") {
			jsonError(w, http.StatusForbidden, "raw logs require admin scope", requestID(r))
			return
		}
		request := LogRequest{Domain: domain, Sources: input.Sources, AppLogPath: input.AppLogPath, From: input.From, To: input.To, Contains: input.Contains, Statuses: input.Statuses, MaxLines: input.MaxLines, Raw: input.Raw, Symptom: input.Symptom}
		start := time.Now()
		result, err := CallLogHelper(r.Context(), a.Config, request)
		a.auditLogRequest(r, t, "logs."+operation, strings.Join(input.Sources, ","), len(result.Lines), result.Redactions, start, err)
		if err != nil {
			jsonError(w, http.StatusBadRequest, err.Error(), requestID(r))
			return
		}
		if operation == "query" {
			result.Signals = nil
			result.DiagnosisNotice = ""
		}
		jsonResponse(w, http.StatusOK, result)
	default:
		jsonError(w, http.StatusNotFound, "log endpoint not found", requestID(r))
	}
}

func (a *APIServer) siteOperations(w http.ResponseWriter, r *http.Request, parts []string) {
	if len(parts) < 2 || ValidateDomain(parts[0]) != nil {
		jsonError(w, 404, "site operation not found", requestID(r))
		return
	}
	domain, operation := parts[0], parts[1]
	t, _ := r.Context().Value(tokenContextKey{}).(*Token)
	need := ""
	switch operation {
	case "tls":
		need = "tls:read"
	case "deployments":
		need = "files:write"
	case "backups":
		if r.Method == http.MethodGet {
			need = "backups:read"
		} else {
			need = "backups:write"
		}
	}
	if t == nil || !HasScope(t, need) {
		a.denied.Add(1)
		jsonError(w, 403, "insufficient scope", requestID(r))
		return
	}
	start := time.Now()
	var out any
	var err error
	var action string
	switch operation {
	case "tls":
		if r.Method != http.MethodGet || len(parts) != 2 {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		action = "tls.get_status"
		value := TLSDetails{}
		err = CallTypedHelper(r.Context(), a.Config, HelperRequest{TLS: &TLSRequest{Domain: domain}}, &value)
		out = value
	case "deployments":
		if r.Method != http.MethodPost || (len(parts) != 2 && !(len(parts) == 3 && parts[2] == "root")) {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		var in DeployRequest
		d := json.NewDecoder(r.Body)
		d.DisallowUnknownFields()
		if d.Decode(&in) != nil {
			jsonError(w, 400, "invalid JSON deployment request", requestID(r))
			return
		}
		in.Domain = domain
		in.OwnerTokenID = t.ID
		in.Root = len(parts) == 3
		if in.Root {
			action = "file.deploy_root"
		} else {
			action = "file.deploy_artifact"
		}
		value := DeploymentResult{}
		err = CallTypedHelper(r.Context(), a.Config, HelperRequest{Deploy: &in}, &value)
		out = value
	case "backups":
		if len(parts) == 2 && r.Method == http.MethodGet {
			action = "backup.list"
			value := map[string]any{}
			err = CallTypedHelper(r.Context(), a.Config, HelperRequest{Backup: &BackupRequest{Operation: "list", Domain: domain}}, &value)
			out = value
		} else if len(parts) == 2 && r.Method == http.MethodPost {
			var in struct {
				Components string `json:"components"`
			}
			d := json.NewDecoder(r.Body)
			d.DisallowUnknownFields()
			if d.Decode(&in) != nil {
				jsonError(w, 400, "invalid JSON backup request", requestID(r))
				return
			}
			action = "backup.create"
			value := BackupResult{}
			err = CallTypedHelper(r.Context(), a.Config, HelperRequest{Backup: &BackupRequest{Operation: "create", Domain: domain, Components: in.Components}}, &value)
			out = value
		} else if len(parts) == 4 && parts[2] != "" && parts[3] == "restore" && r.Method == http.MethodPost {
			var in struct {
				Components string `json:"components"`
				Confirm    bool   `json:"confirm"`
			}
			d := json.NewDecoder(r.Body)
			d.DisallowUnknownFields()
			if d.Decode(&in) != nil {
				jsonError(w, 400, "invalid JSON restore request", requestID(r))
				return
			}
			action = "backup.restore"
			value := BackupResult{}
			err = CallTypedHelper(r.Context(), a.Config, HelperRequest{Backup: &BackupRequest{Operation: "restore", Domain: domain, BackupID: parts[2], Components: in.Components, Confirm: in.Confirm}}, &value)
			out = value
		} else {
			jsonError(w, 404, "backup endpoint not found", requestID(r))
			return
		}
	default:
		jsonError(w, 404, "site operation not found", requestID(r))
		return
	}
	outcome, detail := "ok", "site operation completed"
	if err != nil {
		outcome, detail = "error", "site operation failed"
	}
	a.State.Audit(requestID(r), t.ID, action, outcome, detail, time.Since(start))
	if err != nil {
		jsonError(w, 400, err.Error(), requestID(r))
		return
	}
	jsonResponse(w, 200, out)
}

func (a *APIServer) siteCron(w http.ResponseWriter, r *http.Request, parts []string) {
	if len(parts) < 2 || parts[1] != "cron-jobs" || ValidateDomain(parts[0]) != nil {
		jsonError(w, http.StatusNotFound, "cron endpoint not found", requestID(r))
		return
	}
	t, _ := r.Context().Value(tokenContextKey{}).(*Token)
	need := "cron:write"
	if r.Method == http.MethodGet {
		need = "cron:read"
	}
	if t == nil || !HasScope(t, need) {
		a.denied.Add(1)
		jsonError(w, http.StatusForbidden, "insufficient scope", requestID(r))
		return
	}
	domain := parts[0]
	request := CronRequest{Domain: domain}
	switch {
	case len(parts) == 2 && r.Method == http.MethodGet:
		request.Operation = cronList
	case len(parts) == 2 && r.Method == http.MethodPost:
		request.Operation = cronCreate
		if err := decodeCronRequest(r, &request); err != nil {
			jsonError(w, http.StatusBadRequest, err.Error(), requestID(r))
			return
		}
	case len(parts) == 3 && r.Method == http.MethodPatch:
		id, err := strconv.ParseInt(parts[2], 10, 64)
		if err != nil || id < 1 {
			jsonError(w, http.StatusNotFound, "cron job not found", requestID(r))
			return
		}
		request.Operation, request.JobID = cronUpdate, id
		if err := decodeCronRequest(r, &request); err != nil {
			jsonError(w, http.StatusBadRequest, err.Error(), requestID(r))
			return
		}
	case len(parts) == 3 && r.Method == http.MethodDelete:
		id, err := strconv.ParseInt(parts[2], 10, 64)
		if err != nil || id < 1 {
			jsonError(w, http.StatusNotFound, "cron job not found", requestID(r))
			return
		}
		request.Operation, request.JobID = cronDelete, id
		if err := decodeCronRequest(r, &request); err != nil {
			jsonError(w, http.StatusBadRequest, err.Error(), requestID(r))
			return
		}
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	start := time.Now()
	out := CronResult{}
	err := CallTypedHelper(r.Context(), a.Config, HelperRequest{Cron: &request}, &out)
	auditAction := "cron." + request.Operation
	if err != nil {
		a.State.Audit(requestID(r), t.ID, auditAction, "error", "site cron operation failed", time.Since(start))
		jsonError(w, http.StatusBadRequest, err.Error(), requestID(r))
		return
	}
	a.State.Audit(requestID(r), t.ID, auditAction, "ok", "site cron operation completed", time.Since(start))
	jsonResponse(w, http.StatusOK, out)
}

func decodeCronRequest(r *http.Request, out *CronRequest) error {
	operation, domain, jobID := out.Operation, out.Domain, out.JobID
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		return errors.New("invalid JSON cron request")
	}
	out.Operation, out.Domain, out.JobID = operation, domain, jobID
	return nil
}

func (a *APIServer) siteSettings(w http.ResponseWriter, r *http.Request, parts []string) {
	if len(parts) < 2 || ValidateDomain(parts[0]) != nil {
		jsonError(w, http.StatusNotFound, "settings endpoint not found", requestID(r))
		return
	}
	domain := parts[0]
	path := strings.Join(parts[1:], "/")
	var operation, scope string
	switch path {
	case "settings":
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		operation, scope = settingsGet, "sites:read"
	case "settings/root-directory":
		if r.Method != http.MethodPatch {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		operation, scope = settingsUpdateRoot, "sites:write"
	case "settings/site-user/password/rotate":
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		operation, scope = settingsRotatePass, "site-users:write"
	case "php":
		if r.Method == http.MethodGet {
			operation, scope = settingsGetPHP, "php:read"
		} else if r.Method == http.MethodPatch {
			operation, scope = settingsUpdatePHP, "php:write"
		} else {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
	case "pagespeed":
		if r.Method == http.MethodGet {
			operation, scope = settingsGetPageSpeed, "pagespeed:read"
		} else if r.Method == http.MethodPatch {
			operation, scope = settingsUpdatePS, "pagespeed:write"
		} else {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
	case "pagespeed/purge":
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		operation, scope = settingsPurgePS, "cache:purge"
	default:
		jsonError(w, http.StatusNotFound, "settings endpoint not found", requestID(r))
		return
	}
	t, _ := r.Context().Value(tokenContextKey{}).(*Token)
	if t == nil || !HasScope(t, scope) {
		a.denied.Add(1)
		jsonError(w, http.StatusForbidden, "insufficient scope", requestID(r))
		return
	}
	req := SettingsRequest{Operation: operation, Domain: domain}
	if r.Method != http.MethodGet {
		d := json.NewDecoder(r.Body)
		d.DisallowUnknownFields()
		if err := d.Decode(&req); err != nil {
			jsonError(w, http.StatusBadRequest, "invalid JSON settings request", requestID(r))
			return
		}
		req.Operation = operation
		req.Domain = domain
	}
	start := time.Now()
	var out any
	err := a.callSettings(r.Context(), req, &out)
	a.auditSettings(r, t, operation, time.Since(start), err)
	if err != nil {
		status := http.StatusBadRequest
		if strings.Contains(err.Error(), "revision conflict") {
			status = http.StatusConflict
		}
		jsonError(w, status, err.Error(), requestID(r))
		return
	}
	jsonResponse(w, http.StatusOK, out)
}

func (a *APIServer) callSettings(ctx context.Context, request SettingsRequest, out *any) error {
	var raw json.RawMessage
	if err := CallSettingsHelper(ctx, a.Config, request, &raw); err != nil {
		return err
	}
	return json.Unmarshal(raw, out)
}
func (a *APIServer) auditSettings(r *http.Request, t *Token, action string, d time.Duration, err error) {
	outcome, detail := "ok", "settings updated"
	if err != nil {
		outcome, detail = "error", "settings request failed"
	}
	a.State.Audit(requestID(r), t.ID, action, outcome, detail, d)
}

func (a *APIServer) auditLogRequest(r *http.Request, token *Token, action, sources string, lines, redactions int, start time.Time, err error) {
	outcome, detail := "ok", fmt.Sprintf("sources=%s lines=%d redactions=%d", sources, lines, redactions)
	if err != nil {
		outcome, detail = "error", "log request failed"
	}
	a.State.Audit(requestID(r), token.ID, action, outcome, detail, time.Since(start))
}
func (a *APIServer) openapi(w http.ResponseWriter, r *http.Request) {
	logRequestSchema := map[string]any{"type": "object", "additionalProperties": false, "properties": map[string]any{
		"sources":      map[string]any{"type": "array", "items": map[string]string{"type": "string"}, "description": "Source IDs returned by /logs/sources; defaults to Nginx and PHP logs"},
		"app_log_path": map[string]string{"type": "string", "description": "Optional site-document-root-relative regular file or directory"},
		"from":         map[string]string{"type": "string", "format": "date-time"},
		"to":           map[string]string{"type": "string", "format": "date-time"},
		"contains":     map[string]any{"type": "string", "maxLength": 200},
		"statuses":     map[string]any{"type": "array", "items": map[string]any{"type": "integer", "minimum": 100, "maximum": 599}},
		"max_lines":    map[string]any{"type": "integer", "minimum": 1, "maximum": maxLogLines, "default": defaultLogLines},
		"raw":          map[string]string{"type": "boolean", "description": "Requires admin scope; false returns redacted output"},
		"symptom":      map[string]any{"type": "string", "maxLength": 500},
	}}
	logResponseSchema := map[string]any{"type": "object", "properties": map[string]any{
		"domain":     map[string]string{"type": "string"},
		"from":       map[string]string{"type": "string", "format": "date-time"},
		"to":         map[string]string{"type": "string", "format": "date-time"},
		"sources":    map[string]any{"type": "array", "items": map[string]any{"$ref": "#/components/schemas/LogSource"}},
		"lines":      map[string]any{"type": "array", "items": map[string]any{"$ref": "#/components/schemas/LogLine"}},
		"signals":    map[string]any{"type": "array", "items": map[string]any{"$ref": "#/components/schemas/LogSignal"}},
		"redactions": map[string]string{"type": "integer"},
		"bytes_read": map[string]string{"type": "integer"},
		"truncated":  map[string]string{"type": "boolean"},
	}}
	response := func(schema any) map[string]any {
		return map[string]any{"200": map[string]any{"description": "Success", "content": map[string]any{"application/json": map[string]any{"schema": schema}}}}
	}
	jsonResponseSchema := func(schema any) map[string]any {
		return map[string]any{"application/json": map[string]any{"schema": schema}}
	}
	jsonResponse(w, 200, map[string]any{"openapi": "3.1.0", "info": map[string]string{"title": "CloudPanel Gateway", "version": "0.1.0"}, "paths": map[string]any{
		"/v1/sites":                                             map[string]any{"post": map[string]string{"summary": "Create a CloudPanel site"}},
		"/v1/actions/{action}":                                  map[string]any{"post": map[string]string{"summary": "Run a documented typed CloudPanel operation"}},
		"/v1/sites/{domain}/logs/sources":                       map[string]any{"get": map[string]any{"summary": "List safe, site-scoped log sources (requires logs:read)", "responses": response(map[string]any{"type": "object", "properties": map[string]any{"domain": map[string]string{"type": "string"}, "sources": map[string]any{"type": "array", "items": map[string]any{"$ref": "#/components/schemas/LogSource"}}}})}},
		"/v1/sites/{domain}/logs/query":                         map[string]any{"post": map[string]any{"summary": "Query bounded site logs (requires logs:read; raw requires admin)", "requestBody": map[string]any{"required": false, "content": jsonResponseSchema(logRequestSchema)}, "responses": response(logResponseSchema)}},
		"/v1/sites/{domain}/logs/diagnose":                      map[string]any{"post": map[string]any{"summary": "Query site logs with deterministic diagnostic signals", "requestBody": map[string]any{"required": false, "content": jsonResponseSchema(logRequestSchema)}, "responses": response(logResponseSchema)}},
		"/v1/sites/{domain}/settings":                           map[string]any{"get": map[string]any{"summary": "Read CloudPanel site settings and revision", "responses": response(map[string]any{"$ref": "#/components/schemas/SiteSettings"})}},
		"/v1/sites/{domain}/settings/root-directory":            map[string]any{"patch": map[string]any{"summary": "Update an htdocs-contained root directory", "responses": response(map[string]any{"$ref": "#/components/schemas/SiteSettings"})}},
		"/v1/sites/{domain}/settings/site-user/password/rotate": map[string]any{"post": map[string]any{"summary": "Rotate the site account password with confirmation", "responses": response(map[string]any{"$ref": "#/components/schemas/PasswordRotation"})}},
		"/v1/sites/{domain}/php":                                map[string]any{"get": map[string]any{"summary": "Read safe PHP settings", "responses": response(map[string]any{"$ref": "#/components/schemas/PHPSettings"})}, "patch": map[string]any{"summary": "Update reviewed PHP settings", "responses": response(map[string]any{"$ref": "#/components/schemas/PHPSettings"})}},
		"/v1/sites/{domain}/pagespeed":                          map[string]any{"get": map[string]any{"summary": "Read PageSpeed settings", "responses": response(map[string]any{"$ref": "#/components/schemas/PageSpeed"})}, "patch": map[string]any{"summary": "Update PageSpeed preset and filters", "responses": response(map[string]any{"$ref": "#/components/schemas/PageSpeed"})}},
		"/v1/sites/{domain}/pagespeed/purge":                    map[string]any{"post": map[string]any{"summary": "Purge the validated per-site PageSpeed cache", "responses": response(map[string]any{"type": "object"})}},
		"/v1/sites/{domain}/cron-jobs":                          map[string]any{"get": map[string]any{"summary": "List CloudPanel site cron jobs (cron:read)", "responses": response(map[string]any{"$ref": "#/components/schemas/CronResult"})}, "post": map[string]any{"summary": "Create a typed cron job (cron:write; raw commands require cron.raw_command policy)", "responses": response(map[string]any{"$ref": "#/components/schemas/CronResult"})}},
		"/v1/sites/{domain}/cron-jobs/{job_id}":                 map[string]any{"patch": map[string]any{"summary": "Update a cron job with its current revision", "responses": response(map[string]any{"$ref": "#/components/schemas/CronResult"})}, "delete": map[string]any{"summary": "Delete a cron job with confirm=true", "responses": response(map[string]any{"$ref": "#/components/schemas/CronResult"})}},
		"/v1/sites/{domain}/tls":                                map[string]any{"get": map[string]any{"summary": "Read certificate details and expiry-based renewal health (tls:read)", "responses": response(map[string]any{"$ref": "#/components/schemas/TLSDetails"})}},
		"/v1/sites/{domain}/deployments":                        map[string]any{"post": map[string]any{"summary": "Deploy a managed ZIP artifact (files:write plus file.deploy_artifact policy)", "responses": response(map[string]any{"$ref": "#/components/schemas/Deployment"})}},
		"/v1/sites/{domain}/deployments/root":                   map[string]any{"post": map[string]any{"summary": "Replace active root after a mandatory safety backup (files:write, file.deploy_root policy, replace=true, confirm=true)", "responses": response(map[string]any{"$ref": "#/components/schemas/Deployment"})}},
		"/v1/projects/inspect":                                  map[string]any{"post": map[string]any{"summary": "Inspect a token-owned source artifact without executing it", "responses": response(map[string]any{"$ref": "#/components/schemas/ProjectInspection"})}},
		"/v1/sites/{domain}/builds":                             map[string]any{"post": map[string]any{"summary": "Policy-gated sandboxed npm build", "responses": response(map[string]any{"$ref": "#/components/schemas/BuildResult"})}},
		"/v1/sites/{domain}/static":                             map[string]any{"get": map[string]any{"summary": "Read static SPA routing", "responses": response(map[string]any{"$ref": "#/components/schemas/StaticSettings"})}, "patch": map[string]any{"summary": "Update managed SPA routing", "responses": response(map[string]any{"$ref": "#/components/schemas/StaticSettings"})}},
		"/v1/sites/{domain}/static/deploy":                      map[string]any{"post": map[string]any{"summary": "Deploy a static release to the active root", "responses": response(map[string]any{"$ref": "#/components/schemas/Deployment"})}},
		"/v1/sites/{domain}/node":                               map[string]any{"get": map[string]any{"summary": "Read Node.js settings", "responses": response(map[string]any{"$ref": "#/components/schemas/NodeSettings"})}, "patch": map[string]any{"summary": "Update Node.js settings", "responses": response(map[string]any{"$ref": "#/components/schemas/NodeSettings"})}},
		"/v1/sites/{domain}/node/status":                        map[string]any{"get": map[string]any{"summary": "Read Node.js runtime status", "responses": response(map[string]any{"$ref": "#/components/schemas/NodeStatus"})}},
		"/v1/sites/{domain}/node/restart":                       map[string]any{"post": map[string]any{"summary": "Restart generated Node.js service", "responses": response(map[string]any{"$ref": "#/components/schemas/NodeStatus"})}},
		"/v1/sites/{domain}/node/releases":                      map[string]any{"get": map[string]any{"summary": "List Node.js releases", "responses": response(map[string]any{"type": "array"})}, "post": map[string]any{"summary": "Deploy a Node.js release", "responses": response(map[string]any{"$ref": "#/components/schemas/NodeStatus"})}},
		"/v1/sites/{domain}/node/rollback":                      map[string]any{"post": map[string]any{"summary": "Rollback a Node.js release", "responses": response(map[string]any{"$ref": "#/components/schemas/NodeStatus"})}},
		"/v1/artifacts/uploads/begin":                           map[string]any{"post": map[string]any{"summary": "Begin a bounded token-owned chunked upload", "responses": response(map[string]any{"type": "object"})}},
		"/v1/artifacts/uploads/{upload_id}/chunk":               map[string]any{"post": map[string]any{"summary": "Store one sequential base64 chunk", "responses": response(map[string]any{"type": "object"})}},
		"/v1/artifacts/uploads/{upload_id}/complete":            map[string]any{"post": map[string]any{"summary": "Validate and finalize a ZIP artifact upload", "responses": response(map[string]any{"$ref": "#/components/schemas/Artifact"})}},
		"/v1/sites/{domain}/backups":                            map[string]any{"get": map[string]any{"summary": "List managed encrypted backups (backups:read)", "responses": response(map[string]any{"type": "object"})}, "post": map[string]any{"summary": "Create a managed encrypted backup (backups:write)", "responses": response(map[string]any{"$ref": "#/components/schemas/BackupResult"})}},
		"/v1/sites/{domain}/backups/{backup_id}/restore":        map[string]any{"post": map[string]any{"summary": "Restore selected components with confirm=true (backups:write plus backup.restore policy)", "responses": response(map[string]any{"$ref": "#/components/schemas/BackupResult"})}},
		"/mcp": map[string]any{"post": map[string]string{"summary": "MCP Streamable HTTP endpoint"}},
	}, "components": map[string]any{"schemas": map[string]any{
		"LogSource":         map[string]any{"type": "object", "properties": map[string]any{"id": map[string]string{"type": "string"}, "kind": map[string]string{"type": "string"}, "path": map[string]string{"type": "string", "description": "Safe relative path only"}, "rotated": map[string]string{"type": "boolean"}, "size": map[string]string{"type": "integer"}, "modified": map[string]string{"type": "string", "format": "date-time"}}},
		"LogLine":           map[string]any{"type": "object", "properties": map[string]any{"source": map[string]string{"type": "string"}, "timestamp": map[string]string{"type": "string", "format": "date-time"}, "timestamp_unknown": map[string]string{"type": "boolean"}, "line": map[string]string{"type": "string"}}},
		"LogSignal":         map[string]any{"type": "object", "properties": map[string]any{"category": map[string]string{"type": "string"}, "count": map[string]string{"type": "integer"}, "sample": map[string]string{"type": "string"}}},
		"SiteSettings":      map[string]any{"type": "object", "properties": map[string]any{"domain": map[string]string{"type": "string"}, "type": map[string]string{"type": "string"}, "site_user": map[string]string{"type": "string"}, "root_directory": map[string]string{"type": "string"}, "revision": map[string]string{"type": "string"}}},
		"PHPSettings":       map[string]any{"type": "object", "properties": map[string]any{"applicable": map[string]string{"type": "boolean"}, "php_version": map[string]string{"type": "string"}, "values": map[string]any{"type": "object", "additionalProperties": map[string]string{"type": "string"}}, "revision": map[string]string{"type": "string"}}},
		"PageSpeed":         map[string]any{"type": "object", "properties": map[string]any{"available": map[string]string{"type": "boolean"}, "enabled": map[string]string{"type": "boolean"}, "preset": map[string]string{"type": "string"}, "revision": map[string]string{"type": "string"}}},
		"CronResult":        map[string]any{"type": "object", "properties": map[string]any{"domain": map[string]string{"type": "string"}, "revision": map[string]string{"type": "string"}, "jobs": map[string]any{"type": "array", "items": map[string]any{"$ref": "#/components/schemas/CronJob"}}}},
		"CronJob":           map[string]any{"type": "object", "properties": map[string]any{"id": map[string]string{"type": "integer"}, "minute": map[string]string{"type": "string"}, "hour": map[string]string{"type": "string"}, "day": map[string]string{"type": "string"}, "month": map[string]string{"type": "string"}, "weekday": map[string]string{"type": "string"}, "runner": map[string]string{"type": "string"}, "target": map[string]string{"type": "string"}, "command": map[string]string{"type": "string"}}},
		"PasswordRotation":  map[string]any{"type": "object", "properties": map[string]any{"site_user": map[string]string{"type": "string"}, "password": map[string]string{"type": "string", "writeOnly": "true"}}},
		"TLSDetails":        map[string]any{"type": "object", "properties": map[string]any{"issuer": map[string]string{"type": "string"}, "subject": map[string]string{"type": "string"}, "expires_at": map[string]string{"type": "string", "format": "date-time"}, "sans": map[string]any{"type": "array", "items": map[string]string{"type": "string"}}, "renewal_health": map[string]string{"type": "string"}}},
		"Deployment":        map[string]any{"type": "object", "properties": map[string]any{"artifact_id": map[string]string{"type": "string"}, "sha256": map[string]string{"type": "string"}, "target_dir": map[string]string{"type": "string"}, "files": map[string]string{"type": "integer"}}},
		"Artifact":          map[string]any{"type": "object", "properties": map[string]any{"id": map[string]string{"type": "string"}, "sha256": map[string]string{"type": "string"}, "size": map[string]string{"type": "integer"}, "expires_at": map[string]string{"type": "string", "format": "date-time"}}},
		"BackupResult":      map[string]any{"type": "object", "properties": map[string]any{"backup": map[string]any{"type": "object"}, "retention": map[string]any{"type": "object"}, "safety_backup_id": map[string]string{"type": "string"}}},
		"ProjectInspection": map[string]any{"type": "object", "properties": map[string]any{"artifact_id": map[string]string{"type": "string"}, "package_manager": map[string]string{"type": "string"}, "has_package_lock": map[string]string{"type": "boolean"}, "framework": map[string]string{"type": "string"}}},
		"BuildResult":       map[string]any{"type": "object", "properties": map[string]any{"build_id": map[string]string{"type": "string"}, "artifact_id": map[string]string{"type": "string"}, "status": map[string]string{"type": "string"}}},
		"StaticSettings":    map[string]any{"type": "object", "properties": map[string]any{"domain": map[string]string{"type": "string"}, "spa_fallback": map[string]string{"type": "boolean"}, "revision": map[string]string{"type": "string"}}},
		"NodeSettings":      map[string]any{"type": "object", "properties": map[string]any{"domain": map[string]string{"type": "string"}, "node_version": map[string]string{"type": "string"}, "app_port": map[string]string{"type": "integer"}, "revision": map[string]string{"type": "string"}}},
		"NodeStatus":        map[string]any{"type": "object", "properties": map[string]any{"unit": map[string]string{"type": "string"}, "node_version": map[string]string{"type": "string"}, "app_port": map[string]string{"type": "integer"}, "service_active": map[string]string{"type": "boolean"}, "loopback_ready": map[string]string{"type": "boolean"}}},
	}}})
}
func (a *APIServer) docs(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = io.WriteString(w, `<!doctype html><title>CloudPanel Gateway API</title><h1>CloudPanel Gateway</h1><p>Use the authenticated <a href="/openapi.json">OpenAPI document</a>. Send bearer tokens only in the Authorization header.</p>`)
}
func (a *APIServer) metrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	fmt.Fprintf(w, "cloudpanel_gateway_requests_total %d\ncloudpanel_gateway_auth_denied_total %d\n", a.requests.Load(), a.denied.Load())
}
func (a *APIServer) newMCP(t *Token) *mcp.Server {
	s := mcp.NewServer(&mcp.Implementation{Name: "cloudpanel-gateway", Version: "0.1.0"}, nil)
	type in struct {
		Args map[string]string `json:"args" jsonschema:"CloudPanel action arguments"`
	}
	type out struct {
		Action   string `json:"action"`
		Output   string `json:"output"`
		ExitCode int    `json:"exit_code"`
	}
	for name, spec := range Actions {
		name, spec := name, spec
		mcp.AddTool(s, &mcp.Tool{Name: "cloudpanel_" + strings.ReplaceAll(name, ".", "_"), Description: "CloudPanel operation: " + name}, func(ctx context.Context, _ *mcp.CallToolRequest, input in) (*mcp.CallToolResult, out, error) {
			if !HasScope(t, spec.Scope) {
				return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "insufficient scope"}}}, out{}, nil
			}
			res, e := CallHelper(ctx, a.Config, name, input.Args)
			if e != nil || !res.OK {
				msg := "operation failed"
				if e != nil {
					msg = e.Error()
				} else {
					msg = res.Error
				}
				return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: msg}}}, out{}, nil
			}
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "operation completed"}}}, out{Action: name, Output: res.Stdout, ExitCode: res.ExitCode}, nil
		})
	}
	mcp.AddTool(s, &mcp.Tool{Name: "cloudpanel_site_logs_list_sources", Description: "List the safe, site-scoped Nginx, PHP, rotated, and discovered application log sources for a CloudPanel site. Read-only; requires logs:read."}, func(ctx context.Context, _ *mcp.CallToolRequest, input mcpLogSourcesInput) (*mcp.CallToolResult, LogSourcesResult, error) {
		if !HasScope(t, "logs:read") {
			return mcpScopeError(), LogSourcesResult{}, nil
		}
		start := time.Now()
		result, err := CallLogSourcesHelper(ctx, a.Config, input.Domain, "")
		a.auditMCPLog(t, "logs.list_sources", "", 0, 0, time.Since(start), err)
		if err != nil {
			return mcpToolError(err), LogSourcesResult{}, nil
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "log sources listed"}}}, result, nil
	})
	registerLogTool := func(name, description, action string, diagnose bool) {
		mcp.AddTool(s, &mcp.Tool{Name: name, Description: description}, func(ctx context.Context, _ *mcp.CallToolRequest, input mcpLogQueryInput) (*mcp.CallToolResult, LogResult, error) {
			if !HasScope(t, "logs:read") {
				return mcpScopeError(), LogResult{}, nil
			}
			if input.Raw && !HasScope(t, "admin") {
				return mcpToolError(fmt.Errorf("raw logs require admin scope")), LogResult{}, nil
			}
			request := LogRequest{Domain: input.Domain, Sources: input.Sources, AppLogPath: input.AppLogPath, From: input.From, To: input.To, Contains: input.Contains, Statuses: input.Statuses, MaxLines: input.MaxLines, Raw: input.Raw, Symptom: input.Symptom}
			start := time.Now()
			result, err := CallLogHelper(ctx, a.Config, request)
			a.auditMCPLog(t, action, strings.Join(input.Sources, ","), len(result.Lines), result.Redactions, time.Since(start), err)
			if err != nil {
				return mcpToolError(err), LogResult{}, nil
			}
			if !diagnose {
				result.Signals = nil
				result.DiagnosisNotice = ""
			}
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "read-only log query completed"}}}, result, nil
		})
	}
	registerLogTool("cloudpanel_site_logs_query", "Read bounded, site-scoped Nginx, PHP, or application log lines. Use source IDs from cloudpanel_site_logs_list_sources. Read-only; requires logs:read. Default output is redacted; raw=true requires admin.", "logs.query", false)
	registerLogTool("cloudpanel_site_logs_diagnose", "Read bounded site logs and return deterministic evidence categories for HTTP, upstream, PHP, permissions, missing-file, and database failures. Read-only; requires logs:read.", "logs.diagnose", true)
	settingsCall := func(ctx context.Context, operation, scope string, input SettingsRequest, out any) (*mcp.CallToolResult, error) {
		if !HasScope(t, scope) {
			return mcpScopeError(), nil
		}
		input.Operation = operation
		start := time.Now()
		err := CallSettingsHelper(ctx, a.Config, input, out)
		a.auditMCPLog(t, operation, "", 0, 0, time.Since(start), err)
		if err != nil {
			return mcpToolError(err), nil
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "settings operation completed"}}}, nil
	}
	mcp.AddTool(s, &mcp.Tool{Name: "site_get_settings", Description: "Read CloudPanel site identity, root directory, PHP version, PageSpeed state, TLS status, drift indicators, and revision. Requires sites:read."}, func(ctx context.Context, _ *mcp.CallToolRequest, in mcpSiteInput) (*mcp.CallToolResult, SiteSettings, error) {
		out := SiteSettings{}
		res, err := settingsCall(ctx, settingsGet, "sites:read", SettingsRequest{Domain: in.Domain}, &out)
		return res, out, err
	})
	mcp.AddTool(s, &mcp.Tool{Name: "site_update_root_directory", Description: "Change a site root to an existing htdocs-relative directory. Requires sites:write, the current revision, and confirm=true."}, func(ctx context.Context, _ *mcp.CallToolRequest, in mcpRootInput) (*mcp.CallToolResult, SiteSettings, error) {
		out := SiteSettings{}
		res, err := settingsCall(ctx, settingsUpdateRoot, "sites:write", SettingsRequest{Domain: in.Domain, RootDirectory: in.RootDirectory, IfMatchRevision: in.IfMatchRevision, Confirm: in.Confirm}, &out)
		return res, out, err
	})
	mcp.AddTool(s, &mcp.Tool{Name: "site_rotate_user_password", Description: "Generate and set a new SSH/SFTP password for the site account. Returns the secret once. Requires site-users:write, current revision, and confirm=true."}, func(ctx context.Context, _ *mcp.CallToolRequest, in mcpPasswordInput) (*mcp.CallToolResult, PasswordRotation, error) {
		out := PasswordRotation{}
		res, err := settingsCall(ctx, settingsRotatePass, "site-users:write", SettingsRequest{Domain: in.Domain, IfMatchRevision: in.IfMatchRevision, Confirm: in.Confirm}, &out)
		return res, out, err
	})
	mcp.AddTool(s, &mcp.Tool{Name: "php_get_settings", Description: "Read safe effective PHP settings for a CloudPanel site. Returns not applicable for non-PHP sites. Requires php:read."}, func(ctx context.Context, _ *mcp.CallToolRequest, in mcpSiteInput) (*mcp.CallToolResult, PHPSettings, error) {
		out := PHPSettings{}
		res, err := settingsCall(ctx, settingsGetPHP, "php:read", SettingsRequest{Domain: in.Domain}, &out)
		return res, out, err
	})
	mcp.AddTool(s, &mcp.Tool{Name: "php_update_settings", Description: "Update reviewed PHP limits and safe directives. Requires php:write and the current revision."}, func(ctx context.Context, _ *mcp.CallToolRequest, in mcpPHPUpdateInput) (*mcp.CallToolResult, PHPSettings, error) {
		out := PHPSettings{}
		res, err := settingsCall(ctx, settingsUpdatePHP, "php:write", SettingsRequest{Domain: in.Domain, IfMatchRevision: in.IfMatchRevision, PHPValues: in.Values}, &out)
		return res, out, err
	})
	mcp.AddTool(s, &mcp.Tool{Name: "pagespeed_get_settings", Description: "Read PageSpeed availability, enabled state, filters, and current revision. Requires pagespeed:read."}, func(ctx context.Context, _ *mcp.CallToolRequest, in mcpSiteInput) (*mcp.CallToolResult, PageSpeed, error) {
		out := PageSpeed{}
		res, err := settingsCall(ctx, settingsGetPageSpeed, "pagespeed:read", SettingsRequest{Domain: in.Domain}, &out)
		return res, out, err
	})
	mcp.AddTool(s, &mcp.Tool{Name: "pagespeed_update_settings", Description: "Enable or disable PageSpeed with a reviewed preset and allowlisted filters. Requires pagespeed:write and the current revision."}, func(ctx context.Context, _ *mcp.CallToolRequest, in mcpPageSpeedInput) (*mcp.CallToolResult, PageSpeed, error) {
		out := PageSpeed{}
		res, err := settingsCall(ctx, settingsUpdatePS, "pagespeed:write", SettingsRequest{Domain: in.Domain, IfMatchRevision: in.IfMatchRevision, PageSpeed: &PageSpeedUpdate{Enabled: in.Enabled, Preset: in.Preset, EnableFilters: in.EnableFilters, DisableFilters: in.DisableFilters}}, &out)
		return res, out, err
	})
	mcp.AddTool(s, &mcp.Tool{Name: "pagespeed_purge_cache", Description: "Purge only the target site's PageSpeed cache. Requires cache:purge."}, func(ctx context.Context, _ *mcp.CallToolRequest, in mcpSiteInput) (*mcp.CallToolResult, map[string]any, error) {
		out := map[string]any{}
		res, err := settingsCall(ctx, settingsPurgePS, "cache:purge", SettingsRequest{Domain: in.Domain}, &out)
		return res, out, err
	})
	cronCall := func(ctx context.Context, scope, operation string, in mcpCronInput) (*mcp.CallToolResult, CronResult, error) {
		if !HasScope(t, scope) {
			return mcpScopeError(), CronResult{}, nil
		}
		out := CronResult{}
		request := CronRequest{Operation: operation, Domain: in.Domain, JobID: in.JobID, Minute: in.Minute, Hour: in.Hour, Day: in.Day, Month: in.Month, Weekday: in.Weekday, Runner: in.Runner, Target: in.Target, Args: in.Args, Method: in.Method, URL: in.URL, RawCommand: in.RawCommand, IfMatchRevision: in.IfMatchRevision, Confirm: in.Confirm}
		start := time.Now()
		err := CallTypedHelper(ctx, a.Config, HelperRequest{Cron: &request}, &out)
		a.auditMCP(t, "cron."+operation, start, err)
		if err != nil {
			return mcpToolError(err), CronResult{}, nil
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "cron operation completed"}}}, out, nil
	}
	mcp.AddTool(s, &mcp.Tool{Name: "cron_list", Description: "List CloudPanel-managed cron jobs and the revision required for changes. Requires cron:read."}, func(ctx context.Context, _ *mcp.CallToolRequest, in mcpCronInput) (*mcp.CallToolResult, CronResult, error) {
		return cronCall(ctx, "cron:read", cronList, in)
	})
	mcp.AddTool(s, &mcp.Tool{Name: "cron_create", Description: "Create a site cron job using a typed runner. raw_command additionally requires enabled cron.raw_command policy and confirm=true. Requires cron:write and the current revision."}, func(ctx context.Context, _ *mcp.CallToolRequest, in mcpCronInput) (*mcp.CallToolResult, CronResult, error) {
		return cronCall(ctx, "cron:write", cronCreate, in)
	})
	mcp.AddTool(s, &mcp.Tool{Name: "cron_update", Description: "Update a site cron job using the current revision. Requires cron:write."}, func(ctx context.Context, _ *mcp.CallToolRequest, in mcpCronInput) (*mcp.CallToolResult, CronResult, error) {
		return cronCall(ctx, "cron:write", cronUpdate, in)
	})
	mcp.AddTool(s, &mcp.Tool{Name: "cron_delete", Description: "Delete a site cron job. Requires cron:write, current revision, and confirm=true."}, func(ctx context.Context, _ *mcp.CallToolRequest, in mcpCronInput) (*mcp.CallToolResult, CronResult, error) {
		return cronCall(ctx, "cron:write", cronDelete, in)
	})
	mcp.AddTool(s, &mcp.Tool{Name: "tls_get_status", Description: "Read the active TLS certificate issuer, subject, serial, expiry, SANs, CloudPanel/vhost consistency, and expiry-based renewal health. It never exposes private key material. Requires tls:read."}, func(ctx context.Context, _ *mcp.CallToolRequest, in mcpSiteInput) (*mcp.CallToolResult, TLSDetails, error) {
		if !HasScope(t, "tls:read") {
			return mcpScopeError(), TLSDetails{}, nil
		}
		out := TLSDetails{}
		start := time.Now()
		err := CallTypedHelper(ctx, a.Config, HelperRequest{TLS: &TLSRequest{Domain: in.Domain}}, &out)
		a.auditMCP(t, "tls.get_status", start, err)
		if err != nil {
			return mcpToolError(err), TLSDetails{}, nil
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "TLS status retrieved"}}}, out, nil
	})
	mcp.AddTool(s, &mcp.Tool{Name: "file_deploy_artifact", Description: "Deploy a previously uploaded managed ZIP artifact into an existing site-root-relative directory. Requires files:write and locally enabled file.deploy_artifact policy. Existing non-empty targets additionally require replace=true and confirm=true."}, func(ctx context.Context, _ *mcp.CallToolRequest, in mcpDeployInput) (*mcp.CallToolResult, DeploymentResult, error) {
		if !HasScope(t, "files:write") {
			return mcpScopeError(), DeploymentResult{}, nil
		}
		out := DeploymentResult{}
		start := time.Now()
		err := CallTypedHelper(ctx, a.Config, HelperRequest{Deploy: &DeployRequest{Domain: in.Domain, ArtifactID: in.ArtifactID, TargetDir: in.TargetDir, Replace: in.Replace, Confirm: in.Confirm, OwnerTokenID: t.ID}}, &out)
		a.auditMCP(t, "file.deploy_artifact", start, err)
		if err != nil {
			return mcpToolError(err), DeploymentResult{}, nil
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "artifact deployed"}}}, out, nil
	})
	mcp.AddTool(s, &mcp.Tool{Name: "site_deploy_root_artifact", Description: "Replace a site's active document root from a managed ZIP artifact. It first creates an encrypted files safety backup, then performs an atomic directory swap. Requires files:write, local file.deploy_root policy, replace=true, and confirm=true."}, func(ctx context.Context, _ *mcp.CallToolRequest, in mcpRootDeployInput) (*mcp.CallToolResult, DeploymentResult, error) {
		if !HasScope(t, "files:write") {
			return mcpScopeError(), DeploymentResult{}, nil
		}
		out := DeploymentResult{}
		start := time.Now()
		err := CallTypedHelper(ctx, a.Config, HelperRequest{Deploy: &DeployRequest{Domain: in.Domain, ArtifactID: in.ArtifactID, Replace: in.Replace, Confirm: in.Confirm, Root: true, OwnerTokenID: t.ID}}, &out)
		a.auditMCP(t, "file.deploy_root", start, err)
		if err != nil {
			return mcpToolError(err), DeploymentResult{}, nil
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "site root deployed after safety backup"}}}, out, nil
	})
	mcp.AddTool(s, &mcp.Tool{Name: "static_get_settings", Description: "Read whether a CloudPanel static site has gateway-managed Vite-style SPA fallback routing. Requires sites:read."}, func(ctx context.Context, _ *mcp.CallToolRequest, in mcpSiteInput) (*mcp.CallToolResult, StaticSettings, error) {
		if !HasScope(t, "sites:read") {
			return mcpScopeError(), StaticSettings{}, nil
		}
		out := StaticSettings{}
		start := time.Now()
		err := CallTypedHelper(ctx, a.Config, HelperRequest{Static: &StaticRequest{Operation: staticGetRouting, Domain: in.Domain}}, &out)
		a.auditMCP(t, "static.get_routing", start, err)
		if err != nil {
			return mcpToolError(err), StaticSettings{}, nil
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "static routing retrieved"}}}, out, nil
	})
	mcp.AddTool(s, &mcp.Tool{Name: "static_update_routing", Description: "Enable or disable a gateway-managed safe SPA fallback for a CloudPanel static site. Requires sites:write and the current revision."}, func(ctx context.Context, _ *mcp.CallToolRequest, in struct {
		Domain          string `json:"domain"`
		SPAFallback     bool   `json:"spa_fallback"`
		IfMatchRevision string `json:"if_match_revision"`
	}) (*mcp.CallToolResult, StaticSettings, error) {
		if !HasScope(t, "sites:write") {
			return mcpScopeError(), StaticSettings{}, nil
		}
		out := StaticSettings{}
		start := time.Now()
		err := CallTypedHelper(ctx, a.Config, HelperRequest{Static: &StaticRequest{Operation: staticUpdateRouting, Domain: in.Domain, SPAFallback: in.SPAFallback, IfMatchRevision: in.IfMatchRevision}}, &out)
		a.auditMCP(t, "static.update_routing", start, err)
		if err != nil {
			return mcpToolError(err), StaticSettings{}, nil
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "static routing updated"}}}, out, nil
	})
	mcp.AddTool(s, &mcp.Tool{Name: "static_deploy_release", Description: "Deploy a managed ZIP artifact as a static site's active document root. It validates the site type and creates a mandatory safety backup. Requires files:write, local file.deploy_root policy, replace=true, and confirm=true."}, func(ctx context.Context, _ *mcp.CallToolRequest, in mcpRootDeployInput) (*mcp.CallToolResult, DeploymentResult, error) {
		if !HasScope(t, "files:write") {
			return mcpScopeError(), DeploymentResult{}, nil
		}
		out := DeploymentResult{}
		start := time.Now()
		err := CallTypedHelper(ctx, a.Config, HelperRequest{Deploy: &DeployRequest{Domain: in.Domain, ArtifactID: in.ArtifactID, OwnerTokenID: t.ID, Root: true, Static: true, Replace: in.Replace, Confirm: in.Confirm}}, &out)
		a.auditMCP(t, "static.deploy_release", start, err)
		if err != nil {
			return mcpToolError(err), DeploymentResult{}, nil
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "static release deployed after safety backup"}}}, out, nil
	})
	mcp.AddTool(s, &mcp.Tool{Name: "artifact_begin_upload", Description: "Begin a managed ZIP artifact upload. Supply the exact total number of base64 chunks (1-100), then use artifact_upload_chunk in order and artifact_complete_upload. Requires artifacts:write."}, func(ctx context.Context, _ *mcp.CallToolRequest, in mcpArtifactBeginInput) (*mcp.CallToolResult, map[string]any, error) {
		if !HasScope(t, "artifacts:write") {
			return mcpScopeError(), nil, nil
		}
		out, e := a.beginArtifactUpload(t, in.TotalChunks)
		if e != nil {
			return mcpToolError(e), nil, nil
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "artifact upload session created"}}}, map[string]any{"upload_id": out.ID, "max_chunk_bytes": maxArtifactChunk, "expires_at": out.ExpiresAt}, nil
	})
	mcp.AddTool(s, &mcp.Tool{Name: "artifact_upload_chunk", Description: "Upload one sequential base64 ZIP chunk to a managed artifact session. Each decoded chunk is at most 1 MiB. Requires artifacts:write."}, func(ctx context.Context, _ *mcp.CallToolRequest, in mcpArtifactChunkInput) (*mcp.CallToolResult, map[string]any, error) {
		if !HasScope(t, "artifacts:write") {
			return mcpScopeError(), nil, nil
		}
		if len(in.DataBase64) > base64.StdEncoding.EncodedLen(maxArtifactChunk) {
			return mcpToolError(errors.New("base64 chunk exceeds 1 MiB decoded limit")), nil, nil
		}
		data, e := base64.StdEncoding.DecodeString(in.DataBase64)
		if e != nil {
			return mcpToolError(errors.New("invalid base64 chunk")), nil, nil
		}
		out, e := a.appendArtifactChunk(t, in.UploadID, in.Index, data)
		if e != nil {
			return mcpToolError(e), nil, nil
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "artifact chunk stored"}}}, map[string]any{"upload_id": out.ID, "next_chunk": out.NextChunk, "size": out.Size}, nil
	})
	mcp.AddTool(s, &mcp.Tool{Name: "artifact_complete_upload", Description: "Validate a completed managed ZIP upload, calculate its SHA-256 digest, and return the artifact_id for deployment. Requires artifacts:write."}, func(ctx context.Context, _ *mcp.CallToolRequest, in mcpArtifactCompleteInput) (*mcp.CallToolResult, Artifact, error) {
		if !HasScope(t, "artifacts:write") {
			return mcpScopeError(), Artifact{}, nil
		}
		out, e := a.completeArtifactUpload(t, in.UploadID)
		if e != nil {
			return mcpToolError(e), Artifact{}, nil
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "artifact upload completed"}}}, out, nil
	})
	nodeCall := func(ctx context.Context, scope string, operation string, in mcpNodeInput, out any) (*mcp.CallToolResult, error) {
		if !HasScope(t, scope) {
			return mcpScopeError(), nil
		}
		start := time.Now()
		err := CallTypedHelper(ctx, a.Config, HelperRequest{Node: &NodeRequest{Operation: operation, Domain: in.Domain, ArtifactID: in.ArtifactID, OwnerTokenID: t.ID, Framework: in.Framework, Entrypoint: in.Entrypoint, Args: in.Args, NodeVersion: in.NodeVersion, AppPort: in.AppPort, HealthPath: in.HealthPath, IfMatchRevision: in.IfMatchRevision, Confirm: in.Confirm}}, out)
		a.auditMCP(t, "node."+operation, start, err)
		if err != nil {
			return mcpToolError(err), nil
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "Node.js operation completed"}}}, nil
	}
	mcp.AddTool(s, &mcp.Tool{Name: "project_inspect_artifact", Description: "Read a token-owned source ZIP without executing it. Returns detected npm project characteristics and safe deployment modes. Requires artifacts:write."}, func(ctx context.Context, _ *mcp.CallToolRequest, in mcpNodeInput) (*mcp.CallToolResult, ProjectInspection, error) {
		if !HasScope(t, "artifacts:write") {
			return mcpScopeError(), ProjectInspection{}, nil
		}
		out := ProjectInspection{}
		start := time.Now()
		err := CallTypedHelper(ctx, a.Config, HelperRequest{Node: &NodeRequest{Operation: nodeInspect, Domain: "project.invalid", ArtifactID: in.ArtifactID, OwnerTokenID: t.ID}}, &out)
		a.auditMCP(t, "project.inspect_artifact", start, err)
		if err != nil {
			return mcpToolError(err), ProjectInspection{}, nil
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "project inspected without execution"}}}, out, nil
	})
	mcp.AddTool(s, &mcp.Tool{Name: "site_build_release", Description: "Policy-gated server-side npm build from a token-owned source ZIP. Requires node:build and local node.server_build policy; it runs fixed npm ci and npm run build in a restricted systemd sandbox."}, func(ctx context.Context, _ *mcp.CallToolRequest, in mcpBuildInput) (*mcp.CallToolResult, BuildResult, error) {
		if !HasScope(t, "node:build") {
			return mcpScopeError(), BuildResult{}, nil
		}
		out := BuildResult{}
		start := time.Now()
		err := CallTypedHelper(ctx, a.Config, HelperRequest{Build: &BuildRequest{Domain: in.Domain, ArtifactID: in.ArtifactID, OwnerTokenID: t.ID, Framework: in.Framework, OutputDir: in.OutputDir}}, &out)
		a.auditMCP(t, "node.server_build", start, err)
		if err != nil {
			return mcpToolError(err), BuildResult{}, nil
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "server build completed"}}}, out, nil
	})
	mcp.AddTool(s, &mcp.Tool{Name: "node_get_settings", Description: "Read CloudPanel Node.js version, loopback app port, active release, and revision. Requires node:read."}, func(ctx context.Context, _ *mcp.CallToolRequest, in mcpNodeInput) (*mcp.CallToolResult, NodeSettings, error) {
		out := NodeSettings{}
		res, err := nodeCall(ctx, "node:read", nodeGetSettings, in, &out)
		return res, out, err
	})
	mcp.AddTool(s, &mcp.Tool{Name: "node_update_settings", Description: "Change managed Node.js settings with the current revision and confirm=true. It never performs a build. Requires node:write and local node.runtime_manage policy."}, func(ctx context.Context, _ *mcp.CallToolRequest, in mcpNodeInput) (*mcp.CallToolResult, NodeSettings, error) {
		out := NodeSettings{}
		res, err := nodeCall(ctx, "node:write", nodeUpdate, in, &out)
		return res, out, err
	})
	mcp.AddTool(s, &mcp.Tool{Name: "node_get_status", Description: "Read generated systemd service status, restart count, active release, and loopback readiness. Requires node:read."}, func(ctx context.Context, _ *mcp.CallToolRequest, in mcpNodeInput) (*mcp.CallToolResult, NodeStatus, error) {
		out := NodeStatus{}
		res, err := nodeCall(ctx, "node:read", nodeStatus, in, &out)
		return res, out, err
	})
	mcp.AddTool(s, &mcp.Tool{Name: "node_restart", Description: "Restart the generated site-scoped Node.js systemd unit. Requires node:write, local node.runtime_manage policy, and confirm=true."}, func(ctx context.Context, _ *mcp.CallToolRequest, in mcpNodeInput) (*mcp.CallToolResult, NodeStatus, error) {
		out := NodeStatus{}
		res, err := nodeCall(ctx, "node:write", nodeRestart, in, &out)
		return res, out, err
	})
	mcp.AddTool(s, &mcp.Tool{Name: "node_deploy_release", Description: "Deploy a token-owned managed Node.js ZIP as an immutable release, atomically activate it, and start the hardened generated systemd service. Requires node:deploy and local node.deploy_release policy."}, func(ctx context.Context, _ *mcp.CallToolRequest, in mcpNodeInput) (*mcp.CallToolResult, NodeStatus, error) {
		out := NodeStatus{}
		res, err := nodeCall(ctx, "node:deploy", nodeDeploy, in, &out)
		return res, out, err
	})
	mcp.AddTool(s, &mcp.Tool{Name: "node_list_releases", Description: "List retained Node.js releases for a site. Requires node:read."}, func(ctx context.Context, _ *mcp.CallToolRequest, in mcpNodeInput) (*mcp.CallToolResult, NodeReleaseList, error) {
		out := NodeReleaseList{}
		res, err := nodeCall(ctx, "node:read", nodeList, in, &out)
		return res, out, err
	})
	mcp.AddTool(s, &mcp.Tool{Name: "node_rollback_release", Description: "Atomically reactivate the previous retained Node.js release. Requires node:deploy, local node.deploy_release policy, and confirm=true."}, func(ctx context.Context, _ *mcp.CallToolRequest, in mcpNodeInput) (*mcp.CallToolResult, NodeStatus, error) {
		out := NodeStatus{}
		res, err := nodeCall(ctx, "node:deploy", nodeRollback, in, &out)
		return res, out, err
	})
	mcp.AddTool(s, &mcp.Tool{Name: "site_backup_create", Description: "Create an encrypted, local managed backup of files, databases, or both. Database selection is derived from the CloudPanel site relation. Requires backups:write."}, func(ctx context.Context, _ *mcp.CallToolRequest, in mcpBackupCreateInput) (*mcp.CallToolResult, BackupResult, error) {
		if !HasScope(t, "backups:write") {
			return mcpScopeError(), BackupResult{}, nil
		}
		out := BackupResult{}
		start := time.Now()
		err := CallTypedHelper(ctx, a.Config, HelperRequest{Backup: &BackupRequest{Operation: "create", Domain: in.Domain, Components: in.Components}}, &out)
		a.auditMCP(t, "backup.create", start, err)
		if err != nil {
			return mcpToolError(err), BackupResult{}, nil
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "encrypted backup created"}}}, out, nil
	})
	mcp.AddTool(s, &mcp.Tool{Name: "site_backup_list", Description: "List encrypted local managed recovery backups for a site, including expiry and retention policy. Requires backups:read."}, func(ctx context.Context, _ *mcp.CallToolRequest, in mcpSiteInput) (*mcp.CallToolResult, map[string]any, error) {
		if !HasScope(t, "backups:read") {
			return mcpScopeError(), map[string]any{}, nil
		}
		out := map[string]any{}
		start := time.Now()
		err := CallTypedHelper(ctx, a.Config, HelperRequest{Backup: &BackupRequest{Operation: "list", Domain: in.Domain}}, &out)
		a.auditMCP(t, "backup.list", start, err)
		if err != nil {
			return mcpToolError(err), map[string]any{}, nil
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "backups listed"}}}, out, nil
	})
	mcp.AddTool(s, &mcp.Tool{Name: "site_backup_restore", Description: "Restore selected files, databases, or both from a managed encrypted backup. A mandatory matching pre-restore safety backup is created first. Requires backups:write, locally enabled backup.restore policy, and confirm=true."}, func(ctx context.Context, _ *mcp.CallToolRequest, in mcpBackupRestoreInput) (*mcp.CallToolResult, BackupResult, error) {
		if !HasScope(t, "backups:write") {
			return mcpScopeError(), BackupResult{}, nil
		}
		out := BackupResult{}
		start := time.Now()
		err := CallTypedHelper(ctx, a.Config, HelperRequest{Backup: &BackupRequest{Operation: "restore", Domain: in.Domain, BackupID: in.BackupID, Components: in.Components, Confirm: in.Confirm}}, &out)
		a.auditMCP(t, "backup.restore", start, err)
		if err != nil {
			return mcpToolError(err), BackupResult{}, nil
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "backup restored"}}}, out, nil
	})
	return s
}

func (a *APIServer) auditMCP(t *Token, action string, start time.Time, err error) {
	outcome, detail := "ok", "operation completed"
	if err != nil {
		outcome, detail = "error", "operation failed"
	}
	a.State.Audit("mcp", t.ID, action, outcome, detail, time.Since(start))
}

func mcpScopeError() *mcp.CallToolResult {
	return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "insufficient scope"}}}
}

func mcpToolError(err error) *mcp.CallToolResult {
	return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: err.Error()}}}
}

func (a *APIServer) auditMCPLog(token *Token, action, sources string, lines, redactions int, duration time.Duration, err error) {
	outcome, detail := "ok", fmt.Sprintf("sources=%s lines=%d redactions=%d", sources, lines, redactions)
	if err != nil {
		outcome, detail = "error", "log request failed"
	}
	a.State.Audit("mcp", token.ID, action, outcome, detail, duration)
}
func jsonResponse(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func jsonError(w http.ResponseWriter, status int, message, id string) {
	jsonResponse(w, status, map[string]string{"error": message, "request_id": id})
}
func randomArtifactID() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
