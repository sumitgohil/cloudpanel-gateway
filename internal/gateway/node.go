package gateway

// Node and build operations intentionally use typed requests. They never accept
// a shell command, an arbitrary systemd unit, or an absolute caller path.

import (
	"archive/zip"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	nodeGetSettings = "get_settings"
	nodeUpdate      = "update_settings"
	nodeStatus      = "status"
	nodeRestart     = "restart"
	nodeDeploy      = "deploy_release"
	nodeList        = "list_releases"
	nodeRollback    = "rollback_release"
	nodeInspect     = "inspect_artifact"
)

var (
	nodeEntryRE = regexp.MustCompile(`^[A-Za-z0-9_./-]+\.(?:js|mjs|cjs)$`)
	nodeArgRE   = regexp.MustCompile(`^[A-Za-z0-9_./:=@,+-]{1,200}$`)
	unitSafeRE  = regexp.MustCompile(`^[a-z0-9-]{8,64}$`)
)

type NodeRequest struct {
	Operation       string   `json:"operation"`
	Domain          string   `json:"domain"`
	ArtifactID      string   `json:"artifact_id,omitempty"`
	OwnerTokenID    string   `json:"owner_token_id,omitempty"`
	Framework       string   `json:"framework,omitempty"`
	Entrypoint      string   `json:"entrypoint,omitempty"`
	Args            []string `json:"args,omitempty"`
	NodeVersion     string   `json:"node_version,omitempty"`
	AppPort         int      `json:"app_port,omitempty"`
	HealthPath      string   `json:"health_path,omitempty"`
	IfMatchRevision string   `json:"if_match_revision,omitempty"`
	Confirm         bool     `json:"confirm,omitempty"`
}

type BuildRequest struct {
	Domain       string `json:"domain"`
	ArtifactID   string `json:"artifact_id"`
	OwnerTokenID string `json:"owner_token_id,omitempty"`
	Framework    string `json:"framework"`
	OutputDir    string `json:"output_dir,omitempty"`
}

type ProjectInspection struct {
	ArtifactID       string   `json:"artifact_id"`
	PackageManager   string   `json:"package_manager"`
	HasPackageLock   bool     `json:"has_package_lock"`
	Framework        string   `json:"framework"`
	Scripts          []string `json:"scripts"`
	SupportedModes   []string `json:"supported_modes"`
	BuildRecommended bool     `json:"build_recommended"`
}

type NodeSettings struct {
	Domain        string `json:"domain"`
	NodeVersion   string `json:"node_version"`
	AppPort       int    `json:"app_port"`
	Revision      string `json:"revision"`
	ActiveRelease string `json:"active_release,omitempty"`
	HealthPath    string `json:"health_path,omitempty"`
}

type NodeRelease struct {
	ID          string `json:"id"`
	Domain      string `json:"domain"`
	ArtifactID  string `json:"artifact_id"`
	SHA256      string `json:"sha256"`
	Framework   string `json:"framework"`
	Entrypoint  string `json:"entrypoint"`
	Status      string `json:"status"`
	CreatedAt   string `json:"created_at"`
	ActivatedAt string `json:"activated_at,omitempty"`
}
type NodeReleaseList struct {
	Releases []NodeRelease `json:"releases"`
}

type NodeStatus struct {
	Domain        string `json:"domain"`
	Unit          string `json:"unit"`
	NodeVersion   string `json:"node_version"`
	AppPort       int    `json:"app_port"`
	ActiveRelease string `json:"active_release,omitempty"`
	ServiceActive bool   `json:"service_active"`
	LoopbackReady bool   `json:"loopback_ready"`
	RestartCount  int    `json:"restart_count"`
	HealthPath    string `json:"health_path,omitempty"`
}

type BuildResult struct {
	BuildID    string `json:"build_id"`
	ArtifactID string `json:"artifact_id,omitempty"`
	Status     string `json:"status"`
}

type nodeConfig struct {
	Domain, UnitName, NodeVersion, Entrypoint, HealthPath, ActiveReleaseID, PreviousReleaseID string
	AppPort                                                                                   int
	Args                                                                                      []string
	UpdatedAt                                                                                 string
}

func nodeUnitName(domain string) string {
	h := sha256.Sum256([]byte(domain))
	return "cloudpanel-gateway-node-" + fmt.Sprintf("%x", h[:8]) + ".service"
}

func validateNodeRequest(r NodeRequest) error {
	if err := ValidateDomain(r.Domain); err != nil {
		return err
	}
	if r.Entrypoint != "" && (!nodeEntryRE.MatchString(r.Entrypoint) || strings.HasPrefix(filepath.Clean(r.Entrypoint), "..")) {
		return errors.New("entrypoint must be a safe relative JavaScript file")
	}
	if len(r.Args) > 20 {
		return errors.New("too many node arguments")
	}
	for _, a := range r.Args {
		if !nodeArgRE.MatchString(a) {
			return errors.New("node argument contains unsupported characters")
		}
	}
	if r.HealthPath != "" && (!strings.HasPrefix(r.HealthPath, "/") || strings.Contains(r.HealthPath, "\\") || len(r.HealthPath) > 200) {
		return errors.New("health_path must be a safe relative HTTP path")
	}
	if r.AppPort != 0 && (r.AppPort < 1024 || r.AppPort > 65535) {
		return errors.New("app_port must be between 1024 and 65535")
	}
	return nil
}

func (s *State) nodeConfig(domain string) (nodeConfig, error) {
	var n nodeConfig
	var args string
	err := s.DB.QueryRow(`SELECT domain,unit_name,node_version,app_port,entrypoint,args,COALESCE(health_path,''),COALESCE(active_release_id,''),COALESCE(previous_release_id,''),updated_at FROM node_configs WHERE domain=?`, domain).Scan(&n.Domain, &n.UnitName, &n.NodeVersion, &n.AppPort, &n.Entrypoint, &args, &n.HealthPath, &n.ActiveReleaseID, &n.PreviousReleaseID, &n.UpdatedAt)
	if err != nil {
		return n, err
	}
	if json.Unmarshal([]byte(args), &n.Args) != nil {
		return n, errors.New("stored node configuration is invalid")
	}
	return n, nil
}
func (s *State) putNodeConfig(n nodeConfig) error {
	b, _ := json.Marshal(n.Args)
	_, err := s.DB.Exec(`INSERT INTO node_configs(domain,unit_name,node_version,app_port,entrypoint,args,health_path,active_release_id,previous_release_id,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(domain) DO UPDATE SET unit_name=excluded.unit_name,node_version=excluded.node_version,app_port=excluded.app_port,entrypoint=excluded.entrypoint,args=excluded.args,health_path=excluded.health_path,active_release_id=excluded.active_release_id,previous_release_id=excluded.previous_release_id,updated_at=excluded.updated_at`, n.Domain, n.UnitName, n.NodeVersion, n.AppPort, n.Entrypoint, string(b), nullString(n.HealthPath), nullString(n.ActiveReleaseID), nullString(n.PreviousReleaseID), n.UpdatedAt)
	return err
}
func nullString(s string) any {
	if s == "" {
		return nil
	}
	return s
}
func nodeRevision(n nodeConfig, pepper []byte) string {
	h := hmac.New(sha256.New, pepper)
	_, _ = h.Write([]byte(strings.Join([]string{n.Domain, n.NodeVersion, strconv.Itoa(n.AppPort), n.Entrypoint, strings.Join(n.Args, "\x00"), n.UpdatedAt}, "\x00")))
	return "rev_" + base64.RawURLEncoding.EncodeToString(h.Sum(nil)[:18])
}
func nodeSettings(n nodeConfig, pepper []byte) NodeSettings {
	return NodeSettings{Domain: n.Domain, NodeVersion: n.NodeVersion, AppPort: n.AppPort, Revision: nodeRevision(n, pepper), ActiveRelease: n.ActiveReleaseID, HealthPath: n.HealthPath}
}

func cloudPanelNodeSettings(ctx context.Context, c Config, domain string) (string, int, error) {
	db, err := openCloudPanelDB(c.CloudPanelDatabase)
	if err != nil {
		return "", 0, err
	}
	defer db.Close()
	var version string
	var port int
	if err = db.QueryRowContext(ctx, `SELECT n.nodejs_version,n.port FROM site s JOIN nodejs_settings n ON n.id=s.nodejs_settings_id WHERE s.domain_name=? AND s.type='nodejs'`, domain).Scan(&version, &port); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", 0, errors.New("CloudPanel Node.js site not found")
		}
		return "", 0, err
	}
	if port < 1024 || port > 65535 || version == "" {
		return "", 0, errors.New("invalid CloudPanel Node.js settings")
	}
	return version, port, nil
}

func nodeBinary(version string) (string, error) { return nodeBinaryForUser("", version) }

func nodeBinaryForUser(user, version string) (string, error) {
	if !regexp.MustCompile(`^[0-9]+(?:\.[0-9]+(?:\.[0-9]+)?)?$`).MatchString(strings.TrimPrefix(version, "v")) {
		return "", errors.New("invalid Node.js version")
	}
	v := strings.TrimPrefix(version, "v")
	candidates := []string{filepath.Join("/usr/local/nvm/versions/node", "v"+v, "bin/node"), filepath.Join("/usr/local/nvm/versions/node", v, "bin/node"), "/usr/local/bin/node", "/usr/bin/node"}
	major := strings.Split(v, ".")[0]
	for _, pattern := range []string{filepath.Join("/usr/local/nvm/versions/node", "v"+major+".*", "bin/node"), filepath.Join("/home", user, ".nvm/versions/node", "v"+major+".*", "bin/node")} {
		if matches, err := filepath.Glob(pattern); err == nil {
			candidates = append(matches, candidates...)
		}
	}
	if siteUserRE.MatchString(user) {
		candidates = append([]string{filepath.Join("/home", user, ".nvm/versions/node", "v"+v, "bin/node"), filepath.Join("/home", user, ".nvm/versions/node", v, "bin/node")}, candidates...)
	}
	for _, p := range candidates {
		if info, e := os.Stat(p); e == nil && info.Mode().IsRegular() {
			out, e := exec.Command(p, "--version").Output()
			if e == nil && strings.HasPrefix(strings.TrimSpace(string(out)), "v"+strings.Split(v, ".")[0]+".") {
				return p, nil
			}
		}
	}
	return "", fmt.Errorf("CloudPanel Node.js runtime %s is unavailable", version)
}

func executeNode(ctx context.Context, c Config, s *State, r NodeRequest) (any, error) {
	if err := validateNodeRequest(r); err != nil {
		return nil, err
	}
	switch r.Operation {
	case nodeInspect:
		a, err := ownedArtifact(s, r.ArtifactID, r.OwnerTokenID)
		if err != nil {
			return nil, err
		}
		return inspectProject(a)
	case nodeGetSettings:
		return currentNodeSettings(ctx, c, s, r.Domain)
	case nodeStatus:
		n, err := s.nodeConfig(r.Domain)
		if err != nil {
			return nil, err
		}
		return statusNode(ctx, n)
	case nodeList:
		items, err := listNodeReleases(s, r.Domain)
		return NodeReleaseList{Releases: items}, err
	case nodeUpdate:
		if allowed, _ := s.Allowed("node.runtime_manage"); !allowed {
			return nil, errors.New("operation disabled by server policy")
		}
		if !r.Confirm {
			return nil, errors.New("Node.js settings update requires confirm=true")
		}
		n, err := s.nodeConfig(r.Domain)
		if err != nil {
			return nil, err
		}
		if r.IfMatchRevision == "" || !hmac.Equal([]byte(r.IfMatchRevision), []byte(nodeRevision(n, s.pepper))) {
			return nil, errors.New("settings revision conflict")
		}
		previous := n
		if r.NodeVersion != "" {
			l, layoutErr := layoutForOperation(r.Domain)
			if layoutErr != nil {
				return nil, layoutErr
			}
			if _, err = nodeBinaryForUser(l.user, r.NodeVersion); err != nil {
				return nil, err
			}
			n.NodeVersion = r.NodeVersion
		}
		if r.AppPort != 0 {
			if r.AppPort != n.AppPort && portInUse(r.AppPort) {
				return nil, errors.New("app_port is already in use")
			}
			n.AppPort = r.AppPort
		}
		if r.HealthPath != "" {
			n.HealthPath = r.HealthPath
		}
		if err := updateCloudPanelNodeSettings(ctx, c, r.Domain, n.NodeVersion, n.AppPort); err != nil {
			return nil, err
		}
		if n.ActiveReleaseID != "" {
			var releasePath string
			if err := s.DB.QueryRow(`SELECT path FROM node_releases WHERE id=? AND domain=?`, n.ActiveReleaseID, n.Domain).Scan(&releasePath); err != nil {
				return nil, errors.New("active Node.js release is unavailable")
			}
			layout, err := layoutForOperation(n.Domain)
			if err != nil {
				return nil, err
			}
			if err = writeNodeUnit(n, layout.user, releasePath); err == nil {
				err = systemctl(ctx, "daemon-reload")
			}
			if err == nil {
				err = systemctl(ctx, "restart", n.UnitName)
			}
			if err != nil || !waitNodeReady(ctx, n) {
				_ = updateCloudPanelNodeSettings(ctx, c, r.Domain, previous.NodeVersion, previous.AppPort)
				_ = writeNodeUnit(previous, layout.user, releasePath)
				_ = systemctl(ctx, "daemon-reload")
				_ = systemctl(ctx, "restart", previous.UnitName)
				if err == nil {
					err = errors.New("updated Node.js runtime did not become loopback-ready")
				}
				return nil, err
			}
		}
		n.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
		if err = s.putNodeConfig(n); err != nil {
			return nil, err
		}
		return nodeSettings(n, s.pepper), nil
	case nodeDeploy:
		return deployNodeRelease(ctx, c, s, r)
	case nodeRestart:
		if allowed, _ := s.Allowed("node.runtime_manage"); !allowed {
			return nil, errors.New("operation disabled by server policy")
		}
		if !r.Confirm {
			return nil, errors.New("node restart requires confirm=true")
		}
		n, err := s.nodeConfig(r.Domain)
		if err != nil {
			return nil, err
		}
		if err = systemctl(ctx, "restart", n.UnitName); err != nil {
			return nil, err
		}
		return statusNode(ctx, n)
	case nodeRollback:
		if allowed, _ := s.Allowed("node.deploy_release"); !allowed {
			return nil, errors.New("operation disabled by server policy")
		}
		if !r.Confirm {
			return nil, errors.New("node rollback requires confirm=true")
		}
		return rollbackNodeRelease(ctx, c, s, r.Domain)
	default:
		return nil, errors.New("unsupported node operation")
	}
}

func updateCloudPanelNodeSettings(ctx context.Context, c Config, domain, version string, port int) error {
	db, err := openCloudPanelDB(c.CloudPanelDatabase)
	if err != nil {
		return err
	}
	defer db.Close()
	var oldVersion string
	var oldPort int
	var settingsID int64
	if err = db.QueryRowContext(ctx, `SELECT n.id,n.nodejs_version,n.port FROM site s JOIN nodejs_settings n ON n.id=s.nodejs_settings_id WHERE s.domain_name=? AND s.type='nodejs'`, domain).Scan(&settingsID, &oldVersion, &oldPort); err != nil {
		return errors.New("CloudPanel Node.js site not found")
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE nodejs_settings SET nodejs_version=?,port=?,updated_at=? WHERE id=?`, version, port, nowDB(), settingsID); err != nil {
		_ = tx.Rollback()
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE site SET updated_at=? WHERE domain_name=? AND type='nodejs'`, nowDB(), domain); err != nil {
		_ = tx.Rollback()
		return err
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	vhostPath := filepath.Join("/etc/nginx/sites-enabled", domain+".conf")
	before, err := os.ReadFile(vhostPath)
	if err != nil {
		return err
	}
	updated, err := patchNodeProxyPort(string(before), port)
	if err == nil {
		err = CallNginxCommit(ctx, c, domain, updated)
	}
	if err != nil {
		_, _ = db.ExecContext(ctx, `UPDATE nodejs_settings SET nodejs_version=?,port=?,updated_at=? WHERE id=?`, oldVersion, oldPort, nowDB(), settingsID)
		return err
	}
	return nil
}
func patchNodeProxyPort(vhost string, port int) (string, error) {
	re := regexp.MustCompile(`(?m)(proxy_pass\s+http://127\.0\.0\.1:)([0-9]+)([;/])`)
	if !re.MatchString(vhost) {
		return "", errors.New("unsupported CloudPanel Node.js vhost: loopback proxy not found")
	}
	return re.ReplaceAllString(vhost, "${1}"+strconv.Itoa(port)+"${3}"), nil
}

func currentNodeSettings(ctx context.Context, c Config, s *State, domain string) (NodeSettings, error) {
	n, err := s.nodeConfig(domain)
	if err == nil {
		return nodeSettings(n, s.pepper), nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return NodeSettings{}, err
	}
	v, p, err := cloudPanelNodeSettings(ctx, c, domain)
	if err != nil {
		return NodeSettings{}, err
	}
	n = nodeConfig{Domain: domain, UnitName: nodeUnitName(domain), NodeVersion: v, AppPort: p, UpdatedAt: time.Now().UTC().Format(time.RFC3339)}
	if err = s.putNodeConfig(n); err != nil {
		return NodeSettings{}, err
	}
	return nodeSettings(n, s.pepper), nil
}
func ownedArtifact(s *State, id, owner string) (Artifact, error) {
	if id == "" {
		return Artifact{}, errors.New("artifact_id is required")
	}
	a, err := s.Artifact(id)
	if err != nil {
		return Artifact{}, errors.New("unknown or expired artifact")
	}
	if time.Now().After(a.ExpiresAt) {
		return Artifact{}, errors.New("artifact expired")
	}
	if owner != "" && a.OwnerTokenID != owner {
		return Artifact{}, errors.New("artifact is not owned by this token")
	}
	return a, nil
}

func inspectProject(a Artifact) (ProjectInspection, error) {
	if err := validateArtifactZIP(a.Path); err != nil {
		return ProjectInspection{}, err
	}
	z, closeFn, err := openZIP(a.Path)
	if err != nil {
		return ProjectInspection{}, err
	}
	defer closeFn()
	var pkg struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
		Scripts         map[string]string `json:"scripts"`
	}
	var hasLock bool
	for _, f := range z.File {
		switch filepath.Clean(f.Name) {
		case "package-lock.json":
			hasLock = true
		case "package.json":
			r, e := f.Open()
			if e != nil {
				return ProjectInspection{}, e
			}
			e = json.NewDecoder(io.LimitReader(r, 1<<20)).Decode(&pkg)
			r.Close()
			if e != nil {
				return ProjectInspection{}, errors.New("invalid package.json")
			}
		}
	}
	if pkg.Scripts == nil {
		return ProjectInspection{}, errors.New("source artifact has no package.json")
	}
	scripts := make([]string, 0, len(pkg.Scripts))
	for k := range pkg.Scripts {
		scripts = append(scripts, k)
	}
	sort.Strings(scripts)
	deps := map[string]string{}
	for k, v := range pkg.Dependencies {
		deps[k] = v
	}
	for k, v := range pkg.DevDependencies {
		deps[k] = v
	}
	framework := "generic-node"
	if _, ok := deps["vite"]; ok {
		framework = "vite"
	}
	if _, ok := deps["astro"]; ok {
		framework = "astro"
	}
	if _, ok := deps["next"]; ok {
		framework = "next-standalone"
	}
	if _, ok := deps["nuxt"]; ok {
		framework = "nuxt-node"
	}
	modes := []string{"node"}
	if framework == "vite" || framework == "astro" {
		modes = []string{"static", "node"}
	}
	return ProjectInspection{ArtifactID: a.ID, PackageManager: "npm", HasPackageLock: hasLock, Framework: framework, Scripts: scripts, SupportedModes: modes, BuildRecommended: true}, nil
}
func openZIP(path string) (*zip.Reader, func(), error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, nil, e
	}
	info, e := f.Stat()
	if e != nil {
		f.Close()
		return nil, nil, e
	}
	z, e := zip.NewReader(f, info.Size())
	if e != nil {
		f.Close()
		return nil, nil, e
	}
	return z, func() { _ = f.Close() }, nil
}

func deployNodeRelease(ctx context.Context, c Config, s *State, r NodeRequest) (NodeStatus, error) {
	allowed, e := s.Allowed("node.deploy_release")
	if e != nil || !allowed {
		return NodeStatus{}, errors.New("operation disabled by server policy")
	}
	a, e := ownedArtifact(s, r.ArtifactID, r.OwnerTokenID)
	if e != nil {
		return NodeStatus{}, e
	}
	n, e := s.nodeConfig(r.Domain)
	if e != nil {
		_, e = currentNodeSettings(ctx, c, s, r.Domain)
		if e != nil {
			return NodeStatus{}, e
		}
		n, e = s.nodeConfig(r.Domain)
		if e != nil {
			return NodeStatus{}, e
		}
	}
	if r.Entrypoint == "" {
		return NodeStatus{}, errors.New("entrypoint is required")
	}
	l, e := layoutForOperation(r.Domain)
	if e != nil {
		return NodeStatus{}, e
	}
	if _, e = nodeBinaryForUser(l.user, n.NodeVersion); e != nil {
		return NodeStatus{}, e
	}
	if portInUse(n.AppPort) {
		return NodeStatus{}, errors.New("CloudPanel app port is already in use")
	}
	base := filepath.Join("/home", l.user, "apps", r.Domain, "releases")
	if e = os.MkdirAll(base, 0750); e != nil {
		return NodeStatus{}, e
	}
	uid, gid := uidFor(l.user), gidFor(l.user)
	for _, dir := range []string{filepath.Join("/home", l.user, "apps"), filepath.Join("/home", l.user, "apps", r.Domain), base} {
		if e = os.Chown(dir, uid, gid); e != nil {
			return NodeStatus{}, e
		}
		if e = os.Chmod(dir, 0750); e != nil {
			return NodeStatus{}, e
		}
	}
	releaseID, e := newID("release_", 12)
	if e != nil {
		return NodeStatus{}, e
	}
	stage := filepath.Join(base, ".stage-"+releaseID)
	if e = os.Mkdir(stage, 0700); e != nil {
		return NodeStatus{}, e
	}
	defer os.RemoveAll(stage)
	if _, e = extractZIP(a.Path, stage); e != nil {
		return NodeStatus{}, e
	}
	entry := filepath.Join(stage, r.Entrypoint)
	info, e := os.Stat(entry)
	if e != nil || !info.Mode().IsRegular() {
		return NodeStatus{}, errors.New("entrypoint is not present in release artifact")
	}
	if e = chownTree(stage, uid, gid); e != nil {
		return NodeStatus{}, e
	}
	release := filepath.Join(base, releaseID)
	if e = os.Rename(stage, release); e != nil {
		return NodeStatus{}, e
	}
	old := n.ActiveReleaseID
	current := filepath.Join("/home", l.user, "apps", r.Domain, "current")
	tmp := current + ".new"
	_ = os.Remove(tmp)
	if e = os.Symlink(release, tmp); e != nil {
		return NodeStatus{}, e
	}
	if e = os.Rename(tmp, current); e != nil {
		return NodeStatus{}, e
	}
	n.Entrypoint = r.Entrypoint
	n.Args = append([]string(nil), r.Args...)
	n.HealthPath = r.HealthPath
	n.PreviousReleaseID = old
	n.ActiveReleaseID = releaseID
	n.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	if e = writeNodeUnit(n, l.user, release); e != nil {
		return NodeStatus{}, e
	}
	if e = s.putNodeConfig(n); e != nil {
		return NodeStatus{}, e
	}
	_, e = s.DB.Exec(`INSERT INTO node_releases(id,domain,artifact_id,sha256,framework,entrypoint,path,status,created_at,activated_at) VALUES(?,?,?,?,?,?,?,?,?,?)`, releaseID, r.Domain, a.ID, a.SHA256, normalizeFramework(r.Framework), r.Entrypoint, release, "active", time.Now().UTC().Format(time.RFC3339), time.Now().UTC().Format(time.RFC3339))
	if e != nil {
		return NodeStatus{}, e
	}
	if e = systemctl(ctx, "daemon-reload"); e == nil {
		e = systemctl(ctx, "enable", "--now", n.UnitName)
	}
	if e != nil || !waitNodeReady(ctx, n) {
		if old == "" {
			_ = deactivateFailedNode(ctx, s, n, releaseID)
		} else {
			_ = rollbackNodePointer(ctx, c, s, n, l.user)
		}
		if e == nil {
			e = errors.New("Node.js service did not become loopback-ready")
		}
		return NodeStatus{}, e
	}
	return statusNode(ctx, n)
}

func deactivateFailedNode(ctx context.Context, s *State, n nodeConfig, releaseID string) error {
	_ = systemctl(ctx, "disable", "--now", n.UnitName)
	_ = os.Remove(filepath.Join("/etc/systemd/system", n.UnitName))
	_ = systemctl(ctx, "daemon-reload")
	n.ActiveReleaseID, n.PreviousReleaseID, n.Entrypoint, n.Args, n.HealthPath = "", "", "", nil, ""
	n.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	if err := s.putNodeConfig(n); err != nil {
		return err
	}
	_, _ = s.DB.Exec(`UPDATE node_releases SET status='failed' WHERE id=?`, releaseID)
	return nil
}
func normalizeFramework(v string) string {
	for _, x := range []string{"generic-node", "astro", "next-standalone", "nuxt-node"} {
		if v == x {
			return v
		}
	}
	return "generic-node"
}

func writeNodeUnit(n nodeConfig, user, release string) error {
	if !unitSafeRE.MatchString(strings.TrimSuffix(strings.TrimPrefix(n.UnitName, "cloudpanel-gateway-node-"), ".service")) {
		return errors.New("invalid generated unit name")
	}
	bin, e := nodeBinaryForUser(user, n.NodeVersion)
	if e != nil {
		return e
	}
	if !nodeEntryRE.MatchString(n.Entrypoint) {
		return errors.New("invalid node entrypoint")
	}
	args := append([]string{bin, filepath.Join(release, n.Entrypoint)}, n.Args...)
	for _, a := range args {
		if strings.ContainsAny(a, " \t\r\n\"'") {
			return errors.New("generated Node.js service argument is unsafe")
		}
	}
	// Node/V8 requires executable writable memory for its JIT. Keep the other
	// service restrictions, but do not set MemoryDenyWriteExecute here.
	content := "[Unit]\nDescription=CloudPanel Gateway Node site " + n.Domain + "\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nType=simple\nUser=" + user + "\nGroup=" + user + "\nWorkingDirectory=" + release + "\nEnvironment=NODE_ENV=production\nEnvironment=PORT=" + strconv.Itoa(n.AppPort) + "\nEnvironment=HOST=127.0.0.1\nExecStart=" + strings.Join(args, " ") + "\nRestart=on-failure\nRestartSec=3\nNoNewPrivileges=true\nPrivateTmp=true\nProtectSystem=strict\nProtectHome=read-only\nProtectKernelTunables=true\nProtectKernelModules=true\nProtectControlGroups=true\nRestrictSUIDSGID=true\nLockPersonality=true\nSystemCallArchitectures=native\nRestrictAddressFamilies=AF_UNIX AF_INET AF_INET6\nCapabilityBoundingSet=\nAmbientCapabilities=\nUMask=0027\n\n[Install]\nWantedBy=multi-user.target\n"
	path := filepath.Join("/etc/systemd/system", n.UnitName)
	tmp, err := os.CreateTemp("/etc/systemd/system", ".cpgw-node-")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err = tmp.Chmod(0644); err == nil {
		_, err = tmp.WriteString(content)
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
func systemctl(ctx context.Context, args ...string) error {
	runCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	out, err := exec.CommandContext(runCtx, "systemctl", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemd operation failed: %s", redact(string(out)))
	}
	return nil
}
func portInUse(port int) bool {
	ln, e := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(port))
	if e != nil {
		return true
	}
	_ = ln.Close()
	return false
}
func waitNodeReady(ctx context.Context, n nodeConfig) bool {
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		d := net.Dialer{Timeout: time.Second}
		conn, e := d.DialContext(ctx, "tcp", "127.0.0.1:"+strconv.Itoa(n.AppPort))
		if e == nil {
			_ = conn.Close()
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(500 * time.Millisecond):
		}
	}
	return false
}
func statusNode(ctx context.Context, n nodeConfig) (NodeStatus, error) {
	out := NodeStatus{Domain: n.Domain, Unit: n.UnitName, NodeVersion: n.NodeVersion, AppPort: n.AppPort, ActiveRelease: n.ActiveReleaseID, HealthPath: n.HealthPath}
	e := exec.CommandContext(ctx, "systemctl", "is-active", "--quiet", n.UnitName).Run()
	out.ServiceActive = e == nil
	out.LoopbackReady = waitNodeReady(ctx, n)
	show, e := exec.CommandContext(ctx, "systemctl", "show", n.UnitName, "--property=NRestarts", "--value").Output()
	if e == nil {
		out.RestartCount, _ = strconv.Atoi(strings.TrimSpace(string(show)))
	}
	return out, nil
}
func listNodeReleases(s *State, domain string) ([]NodeRelease, error) {
	rows, e := s.DB.Query(`SELECT id,domain,artifact_id,sha256,framework,entrypoint,status,created_at,COALESCE(activated_at,'') FROM node_releases WHERE domain=? ORDER BY created_at DESC`, domain)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	var out []NodeRelease
	for rows.Next() {
		var x NodeRelease
		if e = rows.Scan(&x.ID, &x.Domain, &x.ArtifactID, &x.SHA256, &x.Framework, &x.Entrypoint, &x.Status, &x.CreatedAt, &x.ActivatedAt); e != nil {
			return nil, e
		}
		out = append(out, x)
	}
	return out, rows.Err()
}
func rollbackNodeRelease(ctx context.Context, c Config, s *State, domain string) (NodeStatus, error) {
	n, e := s.nodeConfig(domain)
	if e != nil {
		return NodeStatus{}, e
	}
	if n.PreviousReleaseID == "" {
		return NodeStatus{}, errors.New("no previous Node.js release is available")
	}
	var path, entry string
	e = s.DB.QueryRow(`SELECT path,entrypoint FROM node_releases WHERE id=? AND domain=?`, n.PreviousReleaseID, domain).Scan(&path, &entry)
	if e != nil {
		return NodeStatus{}, errors.New("previous release is unavailable")
	}
	l, e := layoutForOperation(domain)
	if e != nil {
		return NodeStatus{}, e
	}
	current := filepath.Join("/home", l.user, "apps", domain, "current")
	tmp := current + ".rollback"
	_ = os.Remove(tmp)
	if e = os.Symlink(path, tmp); e != nil {
		return NodeStatus{}, e
	}
	if e = os.Rename(tmp, current); e != nil {
		return NodeStatus{}, e
	}
	active, previous := n.ActiveReleaseID, n.PreviousReleaseID
	n.ActiveReleaseID = previous
	n.PreviousReleaseID = active
	n.Entrypoint = entry
	n.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	if e = writeNodeUnit(n, l.user, path); e != nil {
		return NodeStatus{}, e
	}
	if e = s.putNodeConfig(n); e != nil {
		return NodeStatus{}, e
	}
	if e = systemctl(ctx, "daemon-reload"); e == nil {
		e = systemctl(ctx, "restart", n.UnitName)
	}
	if e != nil || !waitNodeReady(ctx, n) {
		return NodeStatus{}, errors.New("rollback service did not become ready")
	}
	_, _ = s.DB.Exec(`UPDATE node_releases SET status=CASE WHEN id=? THEN 'active' WHEN id=? THEN 'previous' ELSE status END WHERE domain=?`, previous, active, domain)
	return statusNode(ctx, n)
}
func rollbackNodePointer(ctx context.Context, c Config, s *State, n nodeConfig, user string) error {
	if n.PreviousReleaseID == "" {
		return nil
	}
	var path, entry string
	if e := s.DB.QueryRow(`SELECT path,entrypoint FROM node_releases WHERE id=? AND domain=?`, n.PreviousReleaseID, n.Domain).Scan(&path, &entry); e != nil {
		return e
	}
	current := filepath.Join("/home", user, "apps", n.Domain, "current")
	tmp := current + ".rollback"
	_ = os.Remove(tmp)
	if e := os.Symlink(path, tmp); e != nil {
		return e
	}
	if e := os.Rename(tmp, current); e != nil {
		return e
	}
	n.ActiveReleaseID, n.PreviousReleaseID = n.PreviousReleaseID, n.ActiveReleaseID
	n.Entrypoint = entry
	n.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	if e := writeNodeUnit(n, user, path); e != nil {
		return e
	}
	if e := s.putNodeConfig(n); e != nil {
		return e
	}
	if e := systemctl(ctx, "daemon-reload"); e != nil {
		return e
	}
	return systemctl(ctx, "restart", n.UnitName)
}

func executeBuild(ctx context.Context, c Config, s *State, r BuildRequest) (BuildResult, error) {
	if err := ValidateDomain(r.Domain); err != nil {
		return BuildResult{}, err
	}
	if _, err := s.Allowed("node.server_build"); err != nil {
		return BuildResult{}, err
	}
	allowed, _ := s.Allowed("node.server_build")
	if !allowed {
		return BuildResult{}, errors.New("operation disabled by server policy")
	}
	a, err := ownedArtifact(s, r.ArtifactID, r.OwnerTokenID)
	if err != nil {
		return BuildResult{}, err
	}
	inspection, err := inspectProject(a)
	if err != nil {
		return BuildResult{}, err
	}
	if !inspection.HasPackageLock {
		return BuildResult{}, errors.New("server builds require package-lock.json")
	}
	buildID, err := newID("build_", 12)
	if err != nil {
		return BuildResult{}, err
	}
	if err = os.MkdirAll(c.BuildDir, 0700); err != nil {
		return BuildResult{}, err
	}
	work := filepath.Join(c.BuildDir, buildID)
	if err = os.Mkdir(work, 0700); err != nil {
		return BuildResult{}, err
	}
	defer os.RemoveAll(work)
	source := filepath.Join(work, "source")
	if err = os.Mkdir(source, 0700); err != nil {
		return BuildResult{}, err
	}
	if _, err = extractZIP(a.Path, source); err != nil {
		return BuildResult{}, err
	}
	if err = runSandboxedBuild(ctx, source); err != nil {
		return BuildResult{}, err
	}
	out := r.OutputDir
	if out == "" {
		if r.Framework == "vite" || r.Framework == "astro" {
			out = "dist"
		} else {
			out = "."
		}
	}
	if filepath.IsAbs(out) || strings.HasPrefix(filepath.Clean(out), "..") {
		return BuildResult{}, errors.New("output_dir must be source-relative")
	}
	target := filepath.Join(source, filepath.Clean(out))
	if info, e := os.Stat(target); e != nil || !info.IsDir() {
		return BuildResult{}, errors.New("declared build output directory does not exist")
	}
	artifactID, err := newID("artifact_", 18)
	if err != nil {
		return BuildResult{}, err
	}
	path := filepath.Join(c.ArtifactDir, artifactID)
	if err = os.MkdirAll(c.ArtifactDir, 0750); err != nil {
		return BuildResult{}, err
	}
	if err = zipDirectory(target, path); err != nil {
		return BuildResult{}, err
	}
	if err = validateArtifactZIP(path); err != nil {
		return BuildResult{}, err
	}
	info, e := os.Stat(path)
	if e != nil {
		return BuildResult{}, e
	}
	sum, e := shaFile(path)
	if e != nil {
		return BuildResult{}, e
	}
	artifact := Artifact{ID: artifactID, Path: path, SHA256: sum, Size: info.Size(), OwnerTokenID: r.OwnerTokenID, CreatedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(artifactTTL)}
	if err = s.PutArtifact(artifact); err != nil {
		return BuildResult{}, err
	}
	_, _ = s.DB.Exec(`INSERT INTO builds(id,domain,source_artifact_id,mode,framework,output_artifact_id,status,created_at,completed_at) VALUES(?,?,?,?,?,?,?,?,?)`, buildID, r.Domain, a.ID, "server", r.Framework, artifactID, "completed", time.Now().UTC().Format(time.RFC3339), time.Now().UTC().Format(time.RFC3339))
	return BuildResult{BuildID: buildID, ArtifactID: artifactID, Status: "completed"}, nil
}
func runSandboxedBuild(ctx context.Context, source string) error {
	runCtx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	npm, err := npmBinary()
	if err != nil {
		return err
	}
	args := []string{"--quiet", "--wait", "--collect", "--service-type=exec", "--property=DynamicUser=yes", "--property=NoNewPrivileges=yes", "--property=PrivateTmp=yes", "--property=ProtectSystem=strict", "--property=ProtectHome=yes", "--property=RestrictSUIDSGID=yes", "--property=LockPersonality=yes", "--property=MemoryDenyWriteExecute=yes", "--property=RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6", "--property=CPUQuota=200%", "--property=MemoryMax=1G", "--property=TasksMax=256", "--property=WorkingDirectory=" + source, "--property=BindPaths=" + source, npm, "ci", "--foreground-scripts"}
	out, err := exec.CommandContext(runCtx, "systemd-run", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("server npm install failed: %s", redact(string(out)))
	}
	args[len(args)-2] = "run"
	args[len(args)-1] = "build"
	out, err = exec.CommandContext(runCtx, "systemd-run", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("server npm build failed: %s", redact(string(out)))
	}
	return nil
}
func npmBinary() (string, error) {
	for _, path := range []string{"/usr/local/bin/npm", "/usr/bin/npm"} {
		if info, err := os.Stat(path); err == nil && info.Mode().IsRegular() {
			return path, nil
		}
	}
	return "", errors.New("npm is not installed")
}
func zipDirectory(root, out string) error {
	f, e := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return e
	}
	z := zip.NewWriter(f)
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if path == root {
			return nil
		}
		rel, e := filepath.Rel(root, path)
		if e != nil {
			return e
		}
		if info.IsDir() {
			_, e = z.Create(filepath.ToSlash(rel) + "/")
			return e
		}
		if !info.Mode().IsRegular() {
			return errors.New("build output contains unsupported file")
		}
		w, e := z.Create(filepath.ToSlash(rel))
		if e != nil {
			return e
		}
		in, e := os.Open(path)
		if e != nil {
			return e
		}
		_, e = io.Copy(w, in)
		in.Close()
		return e
	})
	if ce := z.Close(); err == nil {
		err = ce
	}
	if ce := f.Close(); err == nil {
		err = ce
	}
	return err
}
func shaFile(path string) (string, error) {
	f, e := os.Open(path)
	if e != nil {
		return "", e
	}
	defer f.Close()
	h := sha256.New()
	_, e = io.Copy(h, f)
	return fmt.Sprintf("%x", h.Sum(nil)), e
}

var _ = runtime.GOARCH
