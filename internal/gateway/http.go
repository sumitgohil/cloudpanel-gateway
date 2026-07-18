package gateway

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
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
	mux.HandleFunc("/v1/sites", a.auth(a.sites, "sites:write"))
	mux.HandleFunc("/v1/actions/", a.auth(a.action, ""))
	return a.limit(a.requestID(mux))
}
func (a *APIServer) limit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 2<<20)
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
	r.Body = http.MaxBytesReader(w, r.Body, 20<<20)
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
	n, e := io.Copy(f, r.Body)
	closeErr := f.Close()
	if e != nil || closeErr != nil {
		_ = os.Remove(path)
		jsonError(w, 400, "artifact upload failed", requestID(r))
		return
	}
	jsonResponse(w, 201, map[string]any{"id": id, "size": n, "expires_in_seconds": 3600})
}
func (a *APIServer) openapi(w http.ResponseWriter, r *http.Request) {
	jsonResponse(w, 200, map[string]any{"openapi": "3.1.0", "info": map[string]string{"title": "CloudPanel Gateway", "version": "0.1.0"}, "paths": map[string]any{"/v1/sites": map[string]any{"post": map[string]string{"summary": "Create a CloudPanel site"}}, "/v1/actions/{action}": map[string]any{"post": map[string]string{"summary": "Run a documented typed CloudPanel operation"}}, "/mcp": map[string]any{"post": map[string]string{"summary": "MCP Streamable HTTP endpoint"}}}})
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
	return s
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
