package gateway

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

const ProtocolVersion = 1

type Config struct {
	Listen             string   `json:"listen"`
	HelperSocket       string   `json:"helper_socket"`
	NginxCommitSocket  string   `json:"nginx_commit_socket"`
	Database           string   `json:"database"`
	CloudPanelDatabase string   `json:"cloudpanel_database"`
	ArtifactDir        string   `json:"artifact_dir"`
	BackupDir          string   `json:"backup_dir"`
	BackupKeyFile      string   `json:"backup_key_file"`
	SecretFile         string   `json:"secret_file"`
	HelperGID          int      `json:"helper_gid"`
	AllowedHosts       []string `json:"allowed_hosts"`
}

func DefaultConfig() Config {
	return Config{Listen: "127.0.0.1:9780", HelperSocket: "/run/cloudpanel-gateway/helper.sock", NginxCommitSocket: "/run/cloudpanel-gateway/nginx-commit.sock", Database: "/var/lib/cloudpanel-gateway/state.db", CloudPanelDatabase: "/home/clp/htdocs/app/data/db.sq3", ArtifactDir: "/var/lib/cloudpanel-gateway/artifacts", BackupDir: "/var/lib/cloudpanel-gateway/backups", BackupKeyFile: "/var/lib/cloudpanel-gateway/backup-key", SecretFile: "/var/lib/cloudpanel-gateway/token-pepper"}
}

func LoadConfig(path string) (Config, error) {
	c := DefaultConfig()
	if path != "" {
		if b, err := os.ReadFile(path); err == nil {
			if err := json.Unmarshal(b, &c); err != nil {
				return c, fmt.Errorf("parse config: %w", err)
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return c, err
		}
	}
	for _, item := range []struct {
		key string
		dst *string
	}{{"CPG_LISTEN", &c.Listen}, {"CPG_HELPER_SOCKET", &c.HelperSocket}, {"CPG_NGINX_COMMIT_SOCKET", &c.NginxCommitSocket}, {"CPG_DATABASE", &c.Database}, {"CPG_CLOUDPANEL_DATABASE", &c.CloudPanelDatabase}, {"CPG_ARTIFACT_DIR", &c.ArtifactDir}, {"CPG_BACKUP_DIR", &c.BackupDir}, {"CPG_BACKUP_KEY_FILE", &c.BackupKeyFile}, {"CPG_SECRET_FILE", &c.SecretFile}} {
		if v := os.Getenv(item.key); v != "" {
			*item.dst = v
		}
	}
	return c, nil
}

func EnsurePrivateFile(path string, n int) ([]byte, error) {
	if b, err := os.ReadFile(path); err == nil {
		return b, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, b, 0600); err != nil {
		return nil, err
	}
	return b, nil
}

type State struct {
	DB     *sql.DB
	pepper []byte
}
type Token struct {
	ID, Label  string
	Scopes     []string
	ExpiresAt  *time.Time
	Revoked    bool
	LastUsedAt *time.Time
	CreatedAt  time.Time
}

func OpenState(c Config, createSecret bool) (*State, error) {
	if err := os.MkdirAll(filepath.Dir(c.Database), 0750); err != nil {
		return nil, err
	}
	pepper, err := os.ReadFile(c.SecretFile)
	if errors.Is(err, os.ErrNotExist) && createSecret {
		pepper, err = EnsurePrivateFile(c.SecretFile, 32)
	}
	if err != nil {
		return nil, fmt.Errorf("read token pepper: %w", err)
	}
	db, err := sql.Open("sqlite", c.Database)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	_, err = db.Exec(`PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS tokens (id TEXT PRIMARY KEY, label TEXT NOT NULL, digest BLOB NOT NULL UNIQUE, scopes TEXT NOT NULL, expires_at TEXT, revoked_at TEXT, last_used_at TEXT, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS policy (operation TEXT PRIMARY KEY, enabled INTEGER NOT NULL, updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS domains (domain TEXT PRIMARY KEY, site_user TEXT NOT NULL, secret BLOB NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS audit (id INTEGER PRIMARY KEY AUTOINCREMENT, request_id TEXT, token_id TEXT, action TEXT NOT NULL, outcome TEXT NOT NULL, detail TEXT, duration_ms INTEGER, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS artifacts (id TEXT PRIMARY KEY, path TEXT NOT NULL, sha256 TEXT NOT NULL, size INTEGER NOT NULL, owner_token_id TEXT NOT NULL, created_at TEXT NOT NULL, expires_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS backups (id TEXT PRIMARY KEY, domain TEXT NOT NULL, components TEXT NOT NULL, databases TEXT NOT NULL, path TEXT NOT NULL, sha256 TEXT NOT NULL, encrypted_size INTEGER NOT NULL, status TEXT NOT NULL, created_at TEXT NOT NULL, expires_at TEXT NOT NULL, safety_backup_of TEXT);`)
	if err != nil {
		db.Close()
		return nil, err
	}
	return &State{DB: db, pepper: pepper}, nil
}
func (s *State) Close() error { return s.DB.Close() }
func newID(prefix string, n int) (string, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	return prefix + base64.RawURLEncoding.EncodeToString(b), err
}
func (s *State) digest(raw string) []byte {
	h := hmac.New(sha256.New, s.pepper)
	h.Write([]byte(raw))
	return h.Sum(nil)
}
func ParseScopes(csv string) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	for _, v := range strings.Split(csv, ",") {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if !scopeRE.MatchString(v) {
			return nil, fmt.Errorf("invalid scope %q", v)
		}
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("at least one scope is required")
	}
	sort.Strings(out)
	return out, nil
}

var scopeRE = regexp.MustCompile(`^(admin|[a-z][a-z0-9-]*:(read|write|admin|purge|permissions|transfer))$`)

func (s *State) CreateToken(label string, scopes []string, expires *time.Time) (Token, string, error) {
	if len(label) < 1 || len(label) > 80 {
		return Token{}, "", errors.New("label must be 1-80 characters")
	}
	raw, err := newID("cp_live_", 32)
	if err != nil {
		return Token{}, "", err
	}
	id, err := newID("tok_", 9)
	if err != nil {
		return Token{}, "", err
	}
	now := time.Now().UTC()
	scopeJSON, _ := json.Marshal(scopes)
	var exp any
	if expires != nil {
		exp = expires.UTC().Format(time.RFC3339)
	}
	_, err = s.DB.Exec(`INSERT INTO tokens(id,label,digest,scopes,expires_at,created_at) VALUES(?,?,?,?,?,?)`, id, label, s.digest(raw), string(scopeJSON), exp, now.Format(time.RFC3339))
	return Token{ID: id, Label: label, Scopes: scopes, ExpiresAt: expires, CreatedAt: now}, raw, err
}
func scanToken(rows *sql.Rows) (Token, error) {
	var t Token
	var scopes, exp, rev, last sql.NullString
	var created string
	if err := rows.Scan(&t.ID, &t.Label, &scopes, &exp, &rev, &last, &created); err != nil {
		return t, err
	}
	_ = json.Unmarshal([]byte(scopes.String), &t.Scopes)
	t.Revoked = rev.Valid
	t.CreatedAt, _ = time.Parse(time.RFC3339, created)
	if exp.Valid {
		v, _ := time.Parse(time.RFC3339, exp.String)
		t.ExpiresAt = &v
	}
	if last.Valid {
		v, _ := time.Parse(time.RFC3339, last.String)
		t.LastUsedAt = &v
	}
	return t, nil
}
func (s *State) ListTokens() ([]Token, error) {
	rows, err := s.DB.Query(`SELECT id,label,scopes,expires_at,revoked_at,last_used_at,created_at FROM tokens ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var all []Token
	for rows.Next() {
		t, e := scanToken(rows)
		if e != nil {
			return nil, e
		}
		all = append(all, t)
	}
	return all, rows.Err()
}
func (s *State) RevokeToken(id string) error {
	r, e := s.DB.Exec(`UPDATE tokens SET revoked_at=? WHERE id=? AND revoked_at IS NULL`, time.Now().UTC().Format(time.RFC3339), id)
	if e != nil {
		return e
	}
	n, _ := r.RowsAffected()
	if n == 0 {
		return errors.New("active token not found")
	}
	return nil
}
func (s *State) Authenticate(raw string) (*Token, error) {
	if !strings.HasPrefix(raw, "cp_live_") {
		return nil, errors.New("invalid bearer token")
	}
	rows, e := s.DB.Query(`SELECT id,label,scopes,expires_at,revoked_at,last_used_at,created_at FROM tokens WHERE digest=?`, s.digest(raw))
	if e != nil {
		return nil, e
	}
	if !rows.Next() {
		_ = rows.Close()
		return nil, errors.New("invalid bearer token")
	}
	t, e := scanToken(rows)
	_ = rows.Close()
	if e != nil {
		return nil, e
	}
	if t.Revoked || (t.ExpiresAt != nil && time.Now().After(*t.ExpiresAt)) {
		return nil, errors.New("inactive bearer token")
	}
	_, _ = s.DB.Exec(`UPDATE tokens SET last_used_at=? WHERE id=?`, time.Now().UTC().Format(time.RFC3339), t.ID)
	return &t, nil
}
func (s *State) Allowed(operation string) (bool, error) {
	var enabled int
	err := s.DB.QueryRow(`SELECT enabled FROM policy WHERE operation=?`, operation).Scan(&enabled)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return enabled == 1, err
}
func (s *State) SetPolicy(operation string, enabled bool) error {
	_, e := s.DB.Exec(`INSERT INTO policy(operation,enabled,updated_at) VALUES(?,?,?) ON CONFLICT(operation) DO UPDATE SET enabled=excluded.enabled,updated_at=excluded.updated_at`, operation, enabled, time.Now().UTC().Format(time.RFC3339))
	return e
}
func (s *State) Audit(requestID, tokenID, action, outcome, detail string, duration time.Duration) {
	_, _ = s.DB.Exec(`INSERT INTO audit(request_id,token_id,action,outcome,detail,duration_ms,created_at) VALUES(?,?,?,?,?,?,?)`, requestID, tokenID, action, outcome, detail, duration.Milliseconds(), time.Now().UTC().Format(time.RFC3339))
}
func (s *State) StoreDomain(domain, user, secret string) error {
	// The generated CloudPanel site password is only needed while the reverse
	// proxy is created. Deliberately do not retain it in gateway state.
	_, e := s.DB.Exec(`INSERT INTO domains(domain,site_user,secret,created_at) VALUES(?,?,?,?) ON CONFLICT(domain) DO UPDATE SET site_user=excluded.site_user,secret=excluded.secret`, domain, user, []byte{}, time.Now().UTC().Format(time.RFC3339))
	return e
}
func (s *State) DeleteDomain(domain string) error {
	_, e := s.DB.Exec(`DELETE FROM domains WHERE domain=?`, domain)
	return e
}
func (s *State) Domain(domain string) (string, string, error) {
	var u string
	var p []byte
	e := s.DB.QueryRow(`SELECT site_user,secret FROM domains WHERE domain=?`, domain).Scan(&u, &p)
	return u, string(p), e
}

type ActionSpec struct {
	Name, Command, Scope string
	Required             []string
	Dangerous            bool
	RunAsSiteUser        bool
}

var Actions = map[string]ActionSpec{
	"cloudflare.update_ips":          {"cloudflare.update_ips", "cloudflare:update:ips", "cloudflare:write", nil, false, false},
	"cloudpanel.enable_basic_auth":   {"cloudpanel.enable_basic_auth", "cloudpanel:enable:basic-auth", "cloudpanel:admin", []string{"userName", "password"}, false, false},
	"cloudpanel.disable_basic_auth":  {"cloudpanel.disable_basic_auth", "cloudpanel:disable:basic-auth", "cloudpanel:admin", nil, false, false},
	"cloudpanel.set_release_channel": {"cloudpanel.set_release_channel", "cloudpanel:set:release-channel", "cloudpanel:admin", []string{"channel"}, false, false},
	"database.master_credentials":    {"database.master_credentials", "db:show:master-credentials", "db:credentials:read", nil, true, false},
	"database.create":                {"database.create", "db:add", "databases:write", []string{"domainName", "databaseName", "databaseUserName", "databaseUserPassword"}, false, false},
	"database.delete":                {"database.delete", "db:delete", "databases:write", []string{"databaseName"}, false, false},
	"database.export":                {"database.export", "db:export", "db:transfer", []string{"databaseName", "file"}, true, false},
	"database.import":                {"database.import", "db:import", "db:transfer", []string{"databaseName", "file"}, true, false},
	"certificate.lets_encrypt":       {"certificate.lets_encrypt", "lets-encrypt:install:certificate", "certificates:write", []string{"domainName"}, false, false},
	"site.create_static":             {"site.create_static", "site:add:static", "sites:write", []string{"domainName", "siteUser", "siteUserPassword"}, false, false},
	"site.create_nodejs":             {"site.create_nodejs", "site:add:nodejs", "sites:write", []string{"domainName", "nodejsVersion", "appPort", "siteUser", "siteUserPassword"}, false, false},
	"site.create_php":                {"site.create_php", "site:add:php", "sites:write", []string{"domainName", "phpVersion", "vhostTemplate", "siteUser", "siteUserPassword"}, false, false},
	"site.create_python":             {"site.create_python", "site:add:python", "sites:write", []string{"domainName", "pythonVersion", "appPort", "siteUser", "siteUserPassword"}, false, false},
	"site.create_reverse_proxy":      {"site.create_reverse_proxy", "site:add:reverse-proxy", "sites:write", []string{"domainName", "reverseProxyUrl", "siteUser", "siteUserPassword"}, false, false},
	"site.delete":                    {"site.delete", "site:delete", "sites:write", []string{"domainName"}, false, false},
	"site.install_certificate":       {"site.install_certificate", "site:install:certificate", "certificates:write", []string{"domainName", "privateKey", "certificate", "certificateChain"}, true, false},
	"system.reset_permissions":       {"system.reset_permissions", "system:permissions:reset", "system:permissions", []string{"directories", "files", "path"}, true, false},
	"user.create":                    {"user.create", "user:add", "users:write", []string{"userName", "email", "firstName", "lastName", "password", "role", "timezone", "status"}, false, false},
	"user.delete":                    {"user.delete", "user:delete", "users:write", []string{"userName"}, false, false},
	"user.list":                      {"user.list", "user:list", "users:read", nil, false, false},
	"user.reset_password":            {"user.reset_password", "user:reset:password", "users:write", []string{"userName", "password"}, false, false},
	"user.disable_mfa":               {"user.disable_mfa", "user:disable:mfa", "users:write", []string{"userName"}, false, false},
	"vhost_template.add":             {"vhost_template.add", "vhost-template:add", "vhosts:write", []string{"name", "file"}, true, false},
	"vhost_template.delete":          {"vhost_template.delete", "vhost-template:delete", "vhosts:write", []string{"name"}, true, false},
	"vhost_template.view":            {"vhost_template.view", "vhost-template:view", "vhosts:read", []string{"name"}, false, false},
	"vhost_templates.import":         {"vhost_templates.import", "vhost-templates:import", "vhosts:write", nil, true, false},
	"vhost_templates.list":           {"vhost_templates.list", "vhost-templates:list", "vhosts:read", nil, false, false},
	"cache.varnish_purge":            {"cache.varnish_purge", "varnish-cache:purge", "cache:purge", []string{"purge", "siteUser"}, false, true},
}

func HasScope(t *Token, needed string) bool {
	for _, s := range t.Scopes {
		if s == "admin" || s == needed {
			return true
		}
	}
	return false
}
func ValidateAction(name string, args map[string]string, artifactDir string) (ActionSpec, error) {
	spec, ok := Actions[name]
	if !ok {
		return spec, errors.New("unsupported action")
	}
	for _, k := range spec.Required {
		if strings.TrimSpace(args[k]) == "" {
			return spec, fmt.Errorf("missing required field %s", k)
		}
	}
	allowed := map[string]bool{}
	for _, k := range append(append([]string{}, spec.Required...), optionalArguments[name]...) {
		allowed[k] = true
	}
	for k, v := range args {
		if !allowed[k] {
			return spec, fmt.Errorf("unsupported argument %s", k)
		}
		if strings.ContainsAny(v, "\x00\r\n") {
			return spec, fmt.Errorf("invalid %s", k)
		}
		if k == "domainName" {
			if err := ValidateDomain(v); err != nil {
				return spec, err
			}
		}
		if k == "appPort" {
			if err := ValidatePort(v); err != nil {
				return spec, err
			}
		}
		if k == "reverseProxyUrl" {
			if err := ValidateURL(v); err != nil {
				return spec, err
			}
		}
		if k == "file" || k == "privateKey" || k == "certificate" || k == "certificateChain" {
			if !safeArtifactPath(v, artifactDir) {
				return spec, errors.New("file must be a managed artifact")
			}
		}
	}
	return spec, nil
}

var optionalArguments = map[string][]string{
	"certificate.lets_encrypt": {"subjectAlternativeName"},
	"user.create":              {"sites"},
}

var domainRE = regexp.MustCompile(`(?i)^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$`)

func ValidateDomain(v string) error {
	if len(v) > 253 || !domainRE.MatchString(v) {
		return fmt.Errorf("invalid domain")
	}
	return nil
}
func ValidatePort(v string) error {
	var p int
	_, e := fmt.Sscan(v, &p)
	if e != nil || p < 1 || p > 65535 {
		return errors.New("invalid port")
	}
	return nil
}
func ValidateURL(v string) error {
	u, e := url.Parse(v)
	if e != nil || !u.IsAbs() || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil {
		return errors.New("invalid reverse proxy URL")
	}
	return nil
}
func safeArtifactPath(path, base string) bool {
	p, e := filepath.Abs(path)
	if e != nil {
		return false
	}
	b, e := filepath.Abs(base)
	if e != nil {
		return false
	}
	return strings.HasPrefix(p, b+string(os.PathSeparator))
}

type HelperRequest struct {
	Version  int               `json:"version"`
	Action   string            `json:"action"`
	Args     map[string]string `json:"args"`
	Log      *LogRequest       `json:"log,omitempty"`
	Settings *SettingsRequest  `json:"settings,omitempty"`
	TLS      *TLSRequest       `json:"tls,omitempty"`
	Deploy   *DeployRequest    `json:"deploy,omitempty"`
	Backup   *BackupRequest    `json:"backup,omitempty"`
}
type HelperResponse struct {
	OK       bool            `json:"ok"`
	Stdout   string          `json:"stdout,omitempty"`
	Stderr   string          `json:"stderr,omitempty"`
	ExitCode int             `json:"exit_code"`
	Error    string          `json:"error,omitempty"`
	Data     json.RawMessage `json:"data,omitempty"`
}

func Execute(ctx context.Context, c Config, s *State, req HelperRequest) HelperResponse {
	if req.Version != ProtocolVersion {
		return HelperResponse{Error: "unsupported helper protocol"}
	}
	if req.Log != nil {
		var value any
		var err error
		if req.Log.ListSources {
			var sources []LogSource
			sources, err = listLogSources(*req.Log)
			value = LogSourcesResult{Domain: req.Log.Domain, Sources: sources}
		} else {
			value, err = readLogs(*req.Log)
		}
		if err != nil {
			return HelperResponse{Error: err.Error()}
		}
		data, err := json.Marshal(value)
		if err != nil {
			return HelperResponse{Error: "encode log result"}
		}
		return HelperResponse{OK: true, Data: data}
	}
	if req.Settings != nil {
		value, err := executeSettings(ctx, c, s, *req.Settings)
		if err != nil {
			return HelperResponse{Error: err.Error()}
		}
		data, err := json.Marshal(value)
		if err != nil {
			return HelperResponse{Error: "encode settings result"}
		}
		return HelperResponse{OK: true, Data: data}
	}
	if req.TLS != nil {
		value, err := inspectTLS(c, *req.TLS)
		if err != nil {
			return HelperResponse{Error: err.Error()}
		}
		data, err := json.Marshal(value)
		if err != nil {
			return HelperResponse{Error: "encode TLS result"}
		}
		return HelperResponse{OK: true, Data: data}
	}
	if req.Deploy != nil {
		value, err := deployArtifact(ctx, c, s, *req.Deploy)
		if err != nil {
			return HelperResponse{Error: err.Error()}
		}
		data, err := json.Marshal(value)
		if err != nil {
			return HelperResponse{Error: "encode deployment result"}
		}
		return HelperResponse{OK: true, Data: data}
	}
	if req.Backup != nil {
		value, err := executeBackup(ctx, c, s, *req.Backup)
		if err != nil {
			return HelperResponse{Error: err.Error()}
		}
		data, err := json.Marshal(value)
		if err != nil {
			return HelperResponse{Error: "encode backup result"}
		}
		return HelperResponse{OK: true, Data: data}
	}
	spec, e := ValidateAction(req.Action, req.Args, c.ArtifactDir)
	if e != nil {
		return HelperResponse{Error: e.Error()}
	}
	if spec.Dangerous {
		allowed, e := s.Allowed(req.Action)
		if e != nil || !allowed {
			return HelperResponse{Error: "operation disabled by server policy"}
		}
	}
	args := []string{spec.Command}
	keys := make([]string, 0, len(req.Args))
	for k := range req.Args {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		args = append(args, "--"+k+"="+req.Args[k])
	}
	cmd := exec.CommandContext(ctx, "clpctl", args...)
	if spec.RunAsSiteUser {
		user := req.Args["siteUser"]
		if user == "" {
			return HelperResponse{Error: "siteUser required"}
		}
		runArgs := append([]string{"-u", user, "--", "clpctl"}, args...)
		cmd = exec.CommandContext(ctx, "runuser", runArgs...)
	}
	out, err := cmd.Output()
	res := HelperResponse{OK: err == nil, Stdout: string(out)}
	if ee := new(exec.ExitError); errors.As(err, &ee) {
		res.Stderr = string(ee.Stderr)
		res.ExitCode = ee.ExitCode()
	}
	if err != nil {
		res.Error = redact(err.Error())
	}
	return res
}
func redact(s string) string {
	for _, k := range []string{"password", "privateKey", "certificateChain", "databaseUserPassword"} {
		s = strings.ReplaceAll(s, k, "[redacted]")
	}
	return s
}
func ListenHelper(ctx context.Context, c Config, s *State) error {
	_ = os.Remove(c.HelperSocket)
	if err := os.MkdirAll(filepath.Dir(c.HelperSocket), 0750); err != nil {
		return err
	}
	ln, e := net.Listen("unix", c.HelperSocket)
	if e != nil {
		return e
	}
	defer ln.Close()
	if e = os.Chmod(c.HelperSocket, 0660); e != nil {
		return e
	}
	if c.HelperGID > 0 {
		if e = os.Chown(c.HelperSocket, 0, c.HelperGID); e != nil {
			return e
		}
	}
	go func() { <-ctx.Done(); ln.Close() }()
	for {
		conn, e := ln.Accept()
		if e != nil {
			if ctx.Err() != nil {
				return nil
			}
			continue
		}
		go func() {
			defer conn.Close()
			var req HelperRequest
			if json.NewDecoder(io.LimitReader(conn, 1<<20)).Decode(&req) != nil {
				return
			}
			timeout := 90 * time.Second
			if req.Backup != nil {
				timeout = 15 * time.Minute
			}
			callCtx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			_ = json.NewEncoder(conn).Encode(Execute(callCtx, c, s, req))
		}()
	}
}
func CallHelper(ctx context.Context, c Config, action string, args map[string]string) (HelperResponse, error) {
	d := net.Dialer{Timeout: 5 * time.Second}
	conn, e := d.DialContext(ctx, "unix", c.HelperSocket)
	if e != nil {
		return HelperResponse{}, e
	}
	defer conn.Close()
	if e = json.NewEncoder(conn).Encode(HelperRequest{Version: ProtocolVersion, Action: action, Args: args}); e != nil {
		return HelperResponse{}, e
	}
	var r HelperResponse
	e = json.NewDecoder(io.LimitReader(conn, 8<<20)).Decode(&r)
	return r, e
}
func CallLogHelper(ctx context.Context, c Config, request LogRequest) (LogResult, error) {
	d := net.Dialer{Timeout: 5 * time.Second}
	conn, e := d.DialContext(ctx, "unix", c.HelperSocket)
	if e != nil {
		return LogResult{}, e
	}
	defer conn.Close()
	if e = json.NewEncoder(conn).Encode(HelperRequest{Version: ProtocolVersion, Log: &request}); e != nil {
		return LogResult{}, e
	}
	var response HelperResponse
	if e = json.NewDecoder(io.LimitReader(conn, 12<<20)).Decode(&response); e != nil {
		return LogResult{}, e
	}
	if !response.OK {
		return LogResult{}, errors.New(response.Error)
	}
	var result LogResult
	if e = json.Unmarshal(response.Data, &result); e != nil {
		return LogResult{}, e
	}
	return result, nil
}

func CallLogSourcesHelper(ctx context.Context, c Config, domain, appLogPath string) (LogSourcesResult, error) {
	d := net.Dialer{Timeout: 5 * time.Second}
	conn, e := d.DialContext(ctx, "unix", c.HelperSocket)
	if e != nil {
		return LogSourcesResult{}, e
	}
	defer conn.Close()
	request := LogRequest{Domain: domain, AppLogPath: appLogPath, ListSources: true}
	if e = json.NewEncoder(conn).Encode(HelperRequest{Version: ProtocolVersion, Log: &request}); e != nil {
		return LogSourcesResult{}, e
	}
	var response HelperResponse
	if e = json.NewDecoder(io.LimitReader(conn, 12<<20)).Decode(&response); e != nil {
		return LogSourcesResult{}, e
	}
	if !response.OK {
		return LogSourcesResult{}, errors.New(response.Error)
	}
	var result LogSourcesResult
	if e = json.Unmarshal(response.Data, &result); e != nil {
		return LogSourcesResult{}, e
	}
	return result, nil
}

func CallSettingsHelper(ctx context.Context, c Config, request SettingsRequest, out any) error {
	d := net.Dialer{Timeout: 5 * time.Second}
	conn, err := d.DialContext(ctx, "unix", c.HelperSocket)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err = json.NewEncoder(conn).Encode(HelperRequest{Version: ProtocolVersion, Settings: &request}); err != nil {
		return err
	}
	var response HelperResponse
	if err = json.NewDecoder(io.LimitReader(conn, 12<<20)).Decode(&response); err != nil {
		return err
	}
	if !response.OK {
		return errors.New(response.Error)
	}
	return json.Unmarshal(response.Data, out)
}

func CallTypedHelper(ctx context.Context, c Config, request HelperRequest, out any) error {
	d := net.Dialer{Timeout: 5 * time.Second}
	conn, err := d.DialContext(ctx, "unix", c.HelperSocket)
	if err != nil {
		return err
	}
	defer conn.Close()
	request.Version = ProtocolVersion
	if err = json.NewEncoder(conn).Encode(request); err != nil {
		return err
	}
	var response HelperResponse
	if err = json.NewDecoder(io.LimitReader(conn, 16<<20)).Decode(&response); err != nil {
		return err
	}
	if !response.OK {
		return errors.New(response.Error)
	}
	return json.Unmarshal(response.Data, out)
}
