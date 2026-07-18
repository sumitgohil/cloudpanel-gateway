package gateway

// Privileged TLS, deployment, and backup operations.  This file deliberately
// contains no shell interpolation: every CloudPanel command is an argument
// vector and every filesystem target is derived from the resolved site layout.

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
)

const (
	artifactTTL            = time.Hour
	backupTTL              = 7 * 24 * time.Hour
	backupQuota      int64 = 10 << 30
	maxZIPCompressed int64 = 100 << 20
	maxZIPExpanded   int64 = 512 << 20
	maxZIPEntries          = 10000
	maxZIPRatio      int64 = 100
	backupChunk            = 4 << 20
)

type Artifact struct {
	ID           string    `json:"id"`
	Path         string    `json:"-"`
	SHA256       string    `json:"sha256"`
	Size         int64     `json:"size"`
	OwnerTokenID string    `json:"owner_token_id"`
	CreatedAt    time.Time `json:"created_at"`
	ExpiresAt    time.Time `json:"expires_at"`
}
type TLSRequest struct {
	Domain string `json:"domain"`
}
type TLSDetails struct {
	Domain                      string   `json:"domain"`
	Configured                  bool     `json:"configured"`
	Subject                     string   `json:"subject,omitempty"`
	Issuer                      string   `json:"issuer,omitempty"`
	Serial                      string   `json:"serial,omitempty"`
	ExpiresAt                   string   `json:"expires_at,omitempty"`
	DaysRemaining               int      `json:"days_remaining,omitempty"`
	SANs                        []string `json:"sans,omitempty"`
	VhostConsistent             bool     `json:"vhost_consistent"`
	CertificateRecordConsistent bool     `json:"certificate_record_consistent"`
	RenewalHealth               string   `json:"renewal_health"`
}
type DeployRequest struct {
	Domain       string `json:"domain"`
	ArtifactID   string `json:"artifact_id"`
	TargetDir    string `json:"target_dir"`
	Replace      bool   `json:"replace"`
	Confirm      bool   `json:"confirm"`
	OwnerTokenID string `json:"owner_token_id"`
}
type DeploymentResult struct {
	Domain     string `json:"domain"`
	ArtifactID string `json:"artifact_id"`
	Digest     string `json:"sha256"`
	TargetDir  string `json:"target_dir"`
	Files      int    `json:"files"`
	Replaced   bool   `json:"replaced"`
}
type BackupRequest struct {
	Operation  string `json:"operation"`
	Domain     string `json:"domain"`
	Components string `json:"components,omitempty"`
	BackupID   string `json:"backup_id,omitempty"`
	Confirm    bool   `json:"confirm,omitempty"`
}
type Backup struct {
	ID             string    `json:"id"`
	Domain         string    `json:"domain"`
	Components     string    `json:"components"`
	Databases      []string  `json:"databases"`
	SHA256         string    `json:"sha256"`
	EncryptedSize  int64     `json:"encrypted_size"`
	Status         string    `json:"status"`
	CreatedAt      time.Time `json:"created_at"`
	ExpiresAt      time.Time `json:"expires_at"`
	SafetyBackupOf string    `json:"safety_backup_of,omitempty"`
	Path           string    `json:"-"`
}
type BackupResult struct {
	Backup             Backup    `json:"backup"`
	Retention          Retention `json:"retention"`
	SafetyBackupID     string    `json:"safety_backup_id,omitempty"`
	RestoredComponents string    `json:"restored_components,omitempty"`
}
type Retention struct {
	Days      int    `json:"days"`
	MaxBytes  int64  `json:"max_bytes"`
	ExpiresAt string `json:"expires_at,omitempty"`
	Pruned    int    `json:"pruned"`
}
type backupManifest struct {
	Version    int       `json:"version"`
	Domain     string    `json:"domain"`
	Components string    `json:"components"`
	Databases  []string  `json:"databases"`
	CreatedAt  time.Time `json:"created_at"`
}

func (s *State) PutArtifact(a Artifact) error {
	_, e := s.DB.Exec(`INSERT INTO artifacts(id,path,sha256,size,owner_token_id,created_at,expires_at) VALUES(?,?,?,?,?,?,?)`, a.ID, a.Path, a.SHA256, a.Size, a.OwnerTokenID, a.CreatedAt.UTC().Format(time.RFC3339), a.ExpiresAt.UTC().Format(time.RFC3339))
	return e
}
func (s *State) Artifact(id string) (Artifact, error) {
	var a Artifact
	var created, expires string
	e := s.DB.QueryRow(`SELECT id,path,sha256,size,owner_token_id,created_at,expires_at FROM artifacts WHERE id=?`, id).Scan(&a.ID, &a.Path, &a.SHA256, &a.Size, &a.OwnerTokenID, &created, &expires)
	if e != nil {
		return a, e
	}
	a.CreatedAt, _ = time.Parse(time.RFC3339, created)
	a.ExpiresAt, _ = time.Parse(time.RFC3339, expires)
	return a, nil
}
func (s *State) CleanupArtifacts(now time.Time) error {
	rows, e := s.DB.Query(`SELECT path FROM artifacts WHERE expires_at<=?`, now.UTC().Format(time.RFC3339))
	if e != nil {
		return e
	}
	defer rows.Close()
	var paths []string
	for rows.Next() {
		var p string
		if rows.Scan(&p) == nil {
			paths = append(paths, p)
		}
	}
	for _, p := range paths {
		_ = os.Remove(p)
	}
	_, e = s.DB.Exec(`DELETE FROM artifacts WHERE expires_at<=?`, now.UTC().Format(time.RFC3339))
	return e
}
func (s *State) PutBackup(b Backup) error {
	dbs, _ := json.Marshal(b.Databases)
	_, e := s.DB.Exec(`INSERT INTO backups(id,domain,components,databases,path,sha256,encrypted_size,status,created_at,expires_at,safety_backup_of) VALUES(?,?,?,?,?,?,?,?,?,?,?)`, b.ID, b.Domain, b.Components, string(dbs), b.Path, b.SHA256, b.EncryptedSize, b.Status, b.CreatedAt.UTC().Format(time.RFC3339), b.ExpiresAt.UTC().Format(time.RFC3339), nullIfEmpty(b.SafetyBackupOf))
	return e
}
func nullIfEmpty(v string) any {
	if v == "" {
		return nil
	}
	return v
}
func scanBackup(row *sql.Row) (Backup, error) {
	var b Backup
	var dbs, created, expires string
	var safety sql.NullString
	e := row.Scan(&b.ID, &b.Domain, &b.Components, &dbs, &b.Path, &b.SHA256, &b.EncryptedSize, &b.Status, &created, &expires, &safety)
	if e != nil {
		return b, e
	}
	_ = json.Unmarshal([]byte(dbs), &b.Databases)
	b.CreatedAt, _ = time.Parse(time.RFC3339, created)
	b.ExpiresAt, _ = time.Parse(time.RFC3339, expires)
	b.SafetyBackupOf = safety.String
	return b, nil
}
func (s *State) Backup(id, domain string) (Backup, error) {
	return scanBackup(s.DB.QueryRow(`SELECT id,domain,components,databases,path,sha256,encrypted_size,status,created_at,expires_at,safety_backup_of FROM backups WHERE id=? AND domain=?`, id, domain))
}
func (s *State) Backups(domain string) ([]Backup, error) {
	query := `SELECT id,domain,components,databases,path,sha256,encrypted_size,status,created_at,expires_at,safety_backup_of FROM backups`
	var rows *sql.Rows
	var e error
	if domain == "" {
		rows, e = s.DB.Query(query + ` ORDER BY created_at DESC`)
	} else {
		rows, e = s.DB.Query(query+` WHERE domain=? ORDER BY created_at DESC`, domain)
	}
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	var out []Backup
	for rows.Next() {
		var b Backup
		var dbs, created, expires string
		var safety sql.NullString
		if e = rows.Scan(&b.ID, &b.Domain, &b.Components, &dbs, &b.Path, &b.SHA256, &b.EncryptedSize, &b.Status, &created, &expires, &safety); e != nil {
			return nil, e
		}
		_ = json.Unmarshal([]byte(dbs), &b.Databases)
		b.CreatedAt, _ = time.Parse(time.RFC3339, created)
		b.ExpiresAt, _ = time.Parse(time.RFC3339, expires)
		b.SafetyBackupOf = safety.String
		out = append(out, b)
	}
	return out, rows.Err()
}

func layoutForOperation(domain string) (siteLayout, error) {
	l, e := siteLayoutFor(domain)
	if e == nil {
		return l, nil
	}
	if ValidateDomain(domain) != nil {
		return siteLayout{}, ValidateDomain(domain)
	}
	b, e := os.ReadFile(filepath.Join("/etc/nginx/sites-enabled", domain+".conf"))
	if e != nil {
		return siteLayout{}, errors.New("site vhost not found")
	}
	m := rootDirectiveRE.FindStringSubmatch(string(b))
	if len(m) != 2 {
		return siteLayout{}, errors.New("site document root not found")
	}
	root, e := filepath.EvalSymlinks(m[1])
	if e != nil {
		return siteLayout{}, fmt.Errorf("resolve site document root: %w", e)
	}
	root = filepath.Clean(root)
	p := strings.Split(strings.TrimPrefix(root, "/"), "/")
	if len(p) < 4 || p[0] != "home" || !siteUserRE.MatchString(p[1]) {
		return siteLayout{}, errors.New("site document root is outside the CloudPanel site boundary")
	}
	return siteLayout{domain: domain, root: root, user: p[1], logs: filepath.Join("/home", p[1], "logs")}, nil
}

func inspectTLS(c Config, r TLSRequest) (TLSDetails, error) {
	if e := ValidateDomain(r.Domain); e != nil {
		return TLSDetails{}, e
	}
	out := TLSDetails{Domain: r.Domain, RenewalHealth: "unknown"}
	crtPath := filepath.Join("/etc/nginx/ssl-certificates", r.Domain+".crt")
	b, e := os.ReadFile(crtPath)
	if e != nil {
		if errors.Is(e, os.ErrNotExist) {
			return out, nil
		}
		return out, e
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return out, errors.New("malformed active certificate")
	}
	cert, e := x509.ParseCertificate(block.Bytes)
	if e != nil {
		return out, errors.New("malformed active certificate")
	}
	out.Configured = true
	out.Subject = cert.Subject.String()
	out.Issuer = cert.Issuer.String()
	out.Serial = hex.EncodeToString(cert.SerialNumber.Bytes())
	out.ExpiresAt = cert.NotAfter.UTC().Format(time.RFC3339)
	out.DaysRemaining = int(time.Until(cert.NotAfter).Hours() / 24)
	out.SANs = append(append([]string{}, cert.DNSNames...), ipStrings(cert)...)
	sort.Strings(out.SANs)
	vhost, _ := os.ReadFile(filepath.Join("/etc/nginx/sites-enabled", r.Domain+".conf"))
	out.VhostConsistent = strings.Contains(string(vhost), crtPath)
	db, e := openCloudPanelDB(c.CloudPanelDatabase)
	if e == nil {
		defer db.Close()
		var count int
		q := `SELECT COUNT(1) FROM certificate c JOIN site s ON s.certificate_id=c.id WHERE s.domain_name=?`
		if db.QueryRow(q, r.Domain).Scan(&count) == nil {
			out.CertificateRecordConsistent = count == 1
		}
	}
	if !out.VhostConsistent || !out.CertificateRecordConsistent {
		out.RenewalHealth = "misconfigured"
	} else if time.Now().After(cert.NotAfter) {
		out.RenewalHealth = "expired"
	} else if out.DaysRemaining < 7 {
		out.RenewalHealth = "critical"
	} else if out.DaysRemaining < 30 {
		out.RenewalHealth = "due_soon"
	} else {
		out.RenewalHealth = "healthy"
	}
	return out, nil
}
func ipStrings(c *x509.Certificate) []string {
	out := make([]string, 0, len(c.IPAddresses))
	for _, ip := range c.IPAddresses {
		out = append(out, ip.String())
	}
	return out
}

func deployArtifact(ctx context.Context, c Config, s *State, r DeployRequest) (DeploymentResult, error) {
	if e := ValidateDomain(r.Domain); e != nil {
		return DeploymentResult{}, e
	}
	if r.ArtifactID == "" || len(r.ArtifactID) > 100 {
		return DeploymentResult{}, errors.New("invalid artifact ID")
	}
	if r.TargetDir == "" {
		return DeploymentResult{}, errors.New("target_dir is required")
	}
	allowed, e := s.Allowed("file.deploy_artifact")
	if e != nil || !allowed {
		return DeploymentResult{}, errors.New("operation disabled by server policy")
	}
	_ = s.CleanupArtifacts(time.Now())
	a, e := s.Artifact(r.ArtifactID)
	if e != nil {
		return DeploymentResult{}, errors.New("unknown or expired artifact")
	}
	if time.Now().After(a.ExpiresAt) {
		return DeploymentResult{}, errors.New("artifact expired")
	}
	if r.OwnerTokenID != "" && a.OwnerTokenID != r.OwnerTokenID {
		return DeploymentResult{}, errors.New("artifact is not owned by this token")
	}
	l, e := layoutForOperation(r.Domain)
	if e != nil {
		return DeploymentResult{}, e
	}
	target, e := containedTarget(l.root, r.TargetDir, true)
	if e != nil {
		return DeploymentResult{}, e
	}
	info, e := os.Stat(target)
	exists := e == nil
	if e != nil && !errors.Is(e, os.ErrNotExist) {
		return DeploymentResult{}, e
	}
	if exists && !info.IsDir() {
		return DeploymentResult{}, errors.New("target exists but is not a directory")
	}
	if exists && (!r.Replace || !r.Confirm) {
		return DeploymentResult{}, errors.New("existing target requires replace=true and confirm=true")
	}
	stage := filepath.Join(filepath.Dir(target), ".cpgw-stage-"+filepath.Base(target)+"-"+randomArtifactID())
	if e = os.Mkdir(stage, 0700); e != nil {
		return DeploymentResult{}, e
	}
	defer os.RemoveAll(stage)
	count, e := extractZIP(a.Path, stage)
	if e != nil {
		return DeploymentResult{}, e
	}
	if e = os.Chown(stage, uidFor(l.user), gidFor(l.user)); e != nil {
		return DeploymentResult{}, e
	}
	if e = chownTree(stage, uidFor(l.user), gidFor(l.user)); e != nil {
		return DeploymentResult{}, e
	}
	old := ""
	if exists {
		old = filepath.Join(filepath.Dir(target), ".cpgw-old-"+filepath.Base(target)+"-"+randomArtifactID())
		if e = os.Rename(target, old); e != nil {
			return DeploymentResult{}, e
		}
	}
	if e = os.Rename(stage, target); e != nil {
		if old != "" {
			_ = os.Rename(old, target)
		}
		return DeploymentResult{}, e
	}
	if old != "" {
		_ = os.RemoveAll(old)
	}
	return DeploymentResult{Domain: r.Domain, ArtifactID: a.ID, Digest: a.SHA256, TargetDir: r.TargetDir, Files: count, Replaced: exists}, nil
}
func containedTarget(root, rel string, mustExistParent bool) (string, error) {
	if filepath.IsAbs(rel) || strings.Contains(rel, "\\") {
		return "", errors.New("target_dir must be a relative POSIX path")
	}
	clean := filepath.Clean(rel)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(os.PathSeparator)) {
		return "", errors.New("invalid target_dir")
	}
	target := filepath.Join(root, clean)
	parent := filepath.Dir(target)
	realParent, e := filepath.EvalSymlinks(parent)
	if e != nil {
		if mustExistParent {
			return "", errors.New("target parent must exist")
		}
		realParent = parent
	}
	if realParent != root && !strings.HasPrefix(realParent, root+string(os.PathSeparator)) {
		return "", errors.New("target escapes site root")
	}
	return target, nil
}
func extractZIP(path, dest string) (int, error) {
	f, e := os.Open(path)
	if e != nil {
		return 0, e
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil {
		return 0, e
	}
	if st.Size() > maxZIPCompressed {
		return 0, errors.New("ZIP exceeds 100 MiB compressed limit")
	}
	z, e := zip.NewReader(f, st.Size())
	if e != nil {
		return 0, errors.New("artifact must be a valid ZIP")
	}
	if len(z.File) > maxZIPEntries {
		return 0, errors.New("ZIP has too many entries")
	}
	seen := map[string]bool{}
	var total int64
	count := 0
	for _, v := range z.File {
		name := filepath.Clean(v.Name)
		if name == "." || filepath.IsAbs(v.Name) || strings.HasPrefix(name, ".."+string(os.PathSeparator)) || seen[name] {
			return 0, errors.New("ZIP contains unsafe or duplicate path")
		}
		seen[name] = true
		if v.FileInfo().Mode()&os.ModeSymlink != 0 {
			return 0, errors.New("ZIP symlinks are not permitted")
		}
		total += int64(v.UncompressedSize64)
		if total > maxZIPExpanded || (v.CompressedSize64 > 0 && int64(v.UncompressedSize64) > int64(v.CompressedSize64)*maxZIPRatio) {
			return 0, errors.New("ZIP expansion limit exceeded")
		}
		out := filepath.Join(dest, name)
		if !strings.HasPrefix(out, dest+string(os.PathSeparator)) {
			return 0, errors.New("ZIP path escapes target")
		}
		if v.FileInfo().IsDir() {
			if e = os.MkdirAll(out, 0750); e != nil {
				return 0, e
			}
			continue
		}
		if !v.FileInfo().Mode().IsRegular() {
			return 0, errors.New("ZIP special files are not permitted")
		}
		if e = os.MkdirAll(filepath.Dir(out), 0750); e != nil {
			return 0, e
		}
		in, e := v.Open()
		if e != nil {
			return 0, e
		}
		of, e := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0640)
		if e == nil {
			_, e = io.Copy(of, io.LimitReader(in, maxZIPExpanded+1))
			ce := of.Close()
			if e == nil {
				e = ce
			}
		}
		in.Close()
		if e != nil {
			return 0, e
		}
		count++
	}
	return count, nil
}
func uidFor(name string) int {
	u, e := userLookup(name)
	if e != nil {
		return -1
	}
	return u.uid
}
func gidFor(name string) int {
	u, e := userLookup(name)
	if e != nil {
		return -1
	}
	return u.gid
}

type localUser struct{ uid, gid int }

func userLookup(name string) (localUser, error) {
	var u syscall.Stat_t
	if e := syscall.Stat(filepath.Join("/home", name), &u); e != nil {
		return localUser{}, e
	}
	return localUser{int(u.Uid), int(u.Gid)}, nil
}
func chownTree(root string, uid, gid int) error {
	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		return os.Chown(path, uid, gid)
	})
}

func executeBackup(ctx context.Context, c Config, s *State, r BackupRequest) (any, error) {
	if e := ValidateDomain(r.Domain); e != nil {
		return nil, e
	}
	switch r.Operation {
	case "create":
		return createBackup(ctx, c, s, r.Domain, r.Components, "")
	case "list":
		b, e := s.Backups(r.Domain)
		return map[string]any{"backups": b, "retention": Retention{Days: 7, MaxBytes: backupQuota}}, e
	case "restore":
		if !r.Confirm {
			return nil, errors.New("restore requires confirm=true")
		}
		ok, e := s.Allowed("backup.restore")
		if e != nil || !ok {
			return nil, errors.New("operation disabled by server policy")
		}
		return restoreBackup(ctx, c, s, r)
	default:
		return nil, errors.New("unsupported backup operation")
	}
}
func validComponents(v string) bool { return v == "files" || v == "databases" || v == "both" }
func want(v, k string) bool         { return v == "both" || v == k }
func siteDatabases(c Config, domain string) ([]string, error) {
	db, e := openCloudPanelDB(c.CloudPanelDatabase)
	if e != nil {
		return nil, e
	}
	defer db.Close()
	rows, e := db.Query(`SELECT d.name FROM "database" d JOIN site s ON d.site_id=s.id WHERE s.domain_name=? ORDER BY d.name`, domain)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var n string
		if e = rows.Scan(&n); e != nil {
			return nil, e
		}
		out = append(out, n)
	}
	return out, rows.Err()
}
func createBackup(ctx context.Context, c Config, s *State, domain, components, safetyOf string) (BackupResult, error) {
	if !validComponents(components) {
		return BackupResult{}, errors.New("components must be files, databases, or both")
	}
	l, e := layoutForOperation(domain)
	if e != nil {
		return BackupResult{}, e
	}
	dbs := []string{}
	if want(components, "databases") {
		if dbs, e = siteDatabases(c, domain); e != nil {
			return BackupResult{}, e
		}
	}
	if e = os.MkdirAll(c.BackupDir, 0700); e != nil {
		return BackupResult{}, e
	}
	id, e := newID("backup_", 18)
	if e != nil {
		return BackupResult{}, e
	}
	plain := filepath.Join(c.BackupDir, "."+id+".tar.gz")
	defer os.Remove(plain)
	if e = writeBackupArchive(ctx, plain, l, domain, components, dbs); e != nil {
		return BackupResult{}, e
	}
	key, e := EnsurePrivateFile(c.BackupKeyFile, 32)
	if e != nil {
		return BackupResult{}, e
	}
	path := filepath.Join(c.BackupDir, id+".cpgb")
	sum, size, e := encryptFile(key, plain, path)
	if e != nil {
		return BackupResult{}, e
	}
	if size > backupQuota {
		_ = os.Remove(path)
		return BackupResult{}, errors.New("backup exceeds the 10 GiB retention quota")
	}
	now := time.Now().UTC()
	b := Backup{ID: id, Domain: domain, Components: components, Databases: dbs, Path: path, SHA256: sum, EncryptedSize: size, Status: "completed", CreatedAt: now, ExpiresAt: now.Add(backupTTL), SafetyBackupOf: safetyOf}
	if e = s.PutBackup(b); e != nil {
		_ = os.Remove(path)
		return BackupResult{}, e
	}
	pruned, _ := pruneBackups(s, c.BackupDir, now)
	return BackupResult{Backup: b, Retention: Retention{Days: 7, MaxBytes: backupQuota, ExpiresAt: b.ExpiresAt.Format(time.RFC3339), Pruned: pruned}}, nil
}
func writeBackupArchive(ctx context.Context, path string, l siteLayout, domain, components string, dbs []string) error {
	f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return e
	}
	defer f.Close()
	gz := gzip.NewWriter(f)
	defer gz.Close()
	tw := tar.NewWriter(gz)
	defer tw.Close()
	m, _ := json.Marshal(backupManifest{Version: 1, Domain: domain, Components: components, Databases: dbs, CreatedAt: time.Now().UTC()})
	if e = tw.WriteHeader(&tar.Header{Name: "manifest.json", Mode: 0600, Size: int64(len(m))}); e != nil {
		return e
	}
	if _, e = tw.Write(m); e != nil {
		return e
	}
	if want(components, "files") {
		if e = addTree(tw, l.root, "files"); e != nil {
			return e
		}
	}
	if want(components, "databases") {
		tmp, e := os.MkdirTemp("", "cpgw-db-")
		if e != nil {
			return e
		}
		defer os.RemoveAll(tmp)
		for _, name := range dbs {
			p := filepath.Join(tmp, name+".sql.gz")
			cmd := exec.CommandContext(ctx, "clpctl", "db:export", "--databaseName="+name, "--file="+p)
			if out, e := cmd.CombinedOutput(); e != nil {
				return fmt.Errorf("database export %s failed: %s", name, redact(string(out)))
			}
			if e = addRegular(tw, p, filepath.ToSlash(filepath.Join("databases", name+".sql.gz"))); e != nil {
				return e
			}
		}
	}
	return nil
}
func addTree(tw *tar.Writer, root, prefix string) error {
	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, e := filepath.Rel(root, path)
		if e != nil {
			return e
		}
		if rel == "." {
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 {
			return errors.New("site root contains symlink; backup refuses unsafe files")
		}
		if d.IsDir() {
			return tw.WriteHeader(&tar.Header{Name: filepath.ToSlash(filepath.Join(prefix, rel)) + "/", Mode: 0750, Typeflag: tar.TypeDir})
		}
		if !d.Type().IsRegular() {
			return errors.New("site root contains non-regular file")
		}
		return addRegular(tw, path, filepath.ToSlash(filepath.Join(prefix, rel)))
	})
}
func addRegular(tw *tar.Writer, path, name string) error {
	st, e := os.Stat(path)
	if e != nil {
		return e
	}
	if !st.Mode().IsRegular() {
		return errors.New("non-regular file")
	}
	if e = tw.WriteHeader(&tar.Header{Name: name, Mode: int64(st.Mode().Perm()), Size: st.Size(), ModTime: st.ModTime()}); e != nil {
		return e
	}
	f, e := os.Open(path)
	if e != nil {
		return e
	}
	defer f.Close()
	_, e = io.Copy(tw, f)
	return e
}
func encryptFile(key []byte, in, out string) (string, int64, error) {
	if len(key) != 32 {
		return "", 0, errors.New("invalid backup key")
	}
	src, e := os.Open(in)
	if e != nil {
		return "", 0, e
	}
	defer src.Close()
	dst, e := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return "", 0, e
	}
	defer dst.Close()
	block, _ := aes.NewCipher(key)
	g, _ := cipher.NewGCM(block)
	base := make([]byte, g.NonceSize())
	if _, e = rand.Read(base); e != nil {
		return "", 0, e
	}
	if _, e = dst.Write([]byte("CPGB1")); e != nil {
		return "", 0, e
	}
	if _, e = dst.Write(base); e != nil {
		return "", 0, e
	}
	h := sha256.New()
	buf := make([]byte, backupChunk)
	var i uint64
	for {
		n, er := src.Read(buf)
		if n > 0 {
			nonce := append([]byte{}, base...)
			for j := 0; j < 8; j++ {
				nonce[len(nonce)-1-j] ^= byte(i >> (8 * j))
			}
			sealed := g.Seal(nil, nonce, buf[:n], nil)
			var lenb [4]byte
			lenb[0] = byte(len(sealed) >> 24)
			lenb[1] = byte(len(sealed) >> 16)
			lenb[2] = byte(len(sealed) >> 8)
			lenb[3] = byte(len(sealed))
			if _, e = dst.Write(lenb[:]); e != nil {
				return "", 0, e
			}
			if _, e = dst.Write(sealed); e != nil {
				return "", 0, e
			}
			h.Write(lenb[:])
			h.Write(sealed)
			i++
		}
		if er == io.EOF {
			break
		}
		if er != nil {
			return "", 0, er
		}
	}
	st, e := dst.Stat()
	if e != nil {
		return "", 0, e
	}
	return hex.EncodeToString(h.Sum(nil)), st.Size(), nil
}
func decryptFile(key []byte, in, out, expected string) error {
	src, e := os.Open(in)
	if e != nil {
		return e
	}
	defer src.Close()
	magic := make([]byte, 5)
	if _, e = io.ReadFull(src, magic); e != nil || string(magic) != "CPGB1" {
		return errors.New("invalid backup encryption format")
	}
	block, _ := aes.NewCipher(key)
	g, _ := cipher.NewGCM(block)
	base := make([]byte, g.NonceSize())
	if _, e = io.ReadFull(src, base); e != nil {
		return e
	}
	dst, e := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return e
	}
	defer dst.Close()
	h := sha256.New()
	var i uint64
	for {
		var l [4]byte
		if _, e = io.ReadFull(src, l[:]); e == io.EOF {
			break
		} else if e != nil {
			return e
		}
		n := int(l[0])<<24 | int(l[1])<<16 | int(l[2])<<8 | int(l[3])
		if n < g.Overhead() || n > backupChunk+g.Overhead() {
			return errors.New("invalid encrypted backup chunk")
		}
		v := make([]byte, n)
		if _, e = io.ReadFull(src, v); e != nil {
			return e
		}
		h.Write(l[:])
		h.Write(v)
		nonce := append([]byte{}, base...)
		for j := 0; j < 8; j++ {
			nonce[len(nonce)-1-j] ^= byte(i >> (8 * j))
		}
		plain, e := g.Open(nil, nonce, v, nil)
		if e != nil {
			return errors.New("backup authentication failed")
		}
		if _, e = dst.Write(plain); e != nil {
			return e
		}
		i++
	}
	if !strings.EqualFold(hex.EncodeToString(h.Sum(nil)), expected) {
		return errors.New("backup digest mismatch")
	}
	return nil
}
func pruneBackups(s *State, dir string, now time.Time) (int, error) {
	all, err := s.Backups("")
	if err != nil {
		return 0, err
	}
	// Backups are returned newest first. Remove expired first, then oldest
	// completed records until the aggregate encrypted storage is within quota.
	remove := func(b Backup) error {
		_ = os.Remove(b.Path)
		_, e := s.DB.Exec(`DELETE FROM backups WHERE id=?`, b.ID)
		return e
	}
	removed, total := 0, int64(0)
	var active []Backup
	for _, b := range all {
		if !b.ExpiresAt.After(now) {
			if err := remove(b); err != nil {
				return removed, err
			}
			removed++
			continue
		}
		active = append(active, b)
		total += b.EncryptedSize
	}
	for i := len(active) - 1; total > backupQuota && i >= 0; i-- {
		b := active[i]
		if b.Status != "completed" {
			continue
		}
		if err := remove(b); err != nil {
			return removed, err
		}
		total -= b.EncryptedSize
		removed++
	}
	if total > backupQuota {
		return removed, errors.New("backup retention quota cannot be satisfied")
	}
	return removed, nil
}
func restoreBackup(ctx context.Context, c Config, s *State, r BackupRequest) (BackupResult, error) {
	if !validComponents(r.Components) {
		return BackupResult{}, errors.New("components must be files, databases, or both")
	}
	b, e := s.Backup(r.BackupID, r.Domain)
	if e != nil {
		return BackupResult{}, errors.New("backup not found")
	}
	if time.Now().After(b.ExpiresAt) {
		return BackupResult{}, errors.New("backup expired")
	}
	if want(r.Components, "files") && !want(b.Components, "files") || want(r.Components, "databases") && !want(b.Components, "databases") {
		return BackupResult{}, errors.New("requested components are not present in backup")
	}
	safety, e := createBackup(ctx, c, s, r.Domain, r.Components, b.ID)
	if e != nil {
		return BackupResult{}, fmt.Errorf("pre-restore safety backup failed: %w", e)
	}
	key, e := EnsurePrivateFile(c.BackupKeyFile, 32)
	if e != nil {
		return BackupResult{}, e
	}
	tmp, e := os.MkdirTemp(c.BackupDir, ".restore-")
	if e != nil {
		return BackupResult{}, e
	}
	defer os.RemoveAll(tmp)
	plain := filepath.Join(tmp, "bundle.tar.gz")
	if e = decryptFile(key, b.Path, plain, b.SHA256); e != nil {
		return BackupResult{}, e
	}
	l, e := layoutForOperation(r.Domain)
	if e != nil {
		return BackupResult{}, e
	}
	if e = restoreArchive(ctx, plain, l, r.Components, b.Databases); e != nil {
		return BackupResult{}, e
	}
	return BackupResult{Backup: b, Retention: Retention{Days: 7, MaxBytes: backupQuota}, SafetyBackupID: safety.Backup.ID, RestoredComponents: r.Components}, nil
}
func restoreArchive(ctx context.Context, plain string, l siteLayout, components string, dbs []string) error {
	f, e := os.Open(plain)
	if e != nil {
		return e
	}
	defer f.Close()
	gz, e := gzip.NewReader(f)
	if e != nil {
		return e
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	stage, e := os.MkdirTemp(filepath.Dir(l.root), ".cpgw-restore-")
	if e != nil {
		return e
	}
	defer os.RemoveAll(stage)
	dbdir := filepath.Join(stage, "db")
	if e = os.Mkdir(dbdir, 0700); e != nil {
		return e
	}
	manifestOK := false
	for {
		h, e := tr.Next()
		if e == io.EOF {
			break
		}
		if e != nil {
			return e
		}
		name := filepath.Clean(h.Name)
		if filepath.IsAbs(h.Name) || strings.HasPrefix(name, "..") {
			return errors.New("backup archive contains unsafe path")
		}
		if name == "manifest.json" {
			v, e := io.ReadAll(io.LimitReader(tr, 1<<20))
			if e != nil {
				return e
			}
			var m backupManifest
			if json.Unmarshal(v, &m) != nil || m.Version != 1 || m.Domain != l.domain {
				return errors.New("backup manifest validation failed")
			}
			manifestOK = true
			continue
		}
		if h.Typeflag != tar.TypeReg && h.Typeflag != tar.TypeDir {
			return errors.New("backup contains special file")
		}
		if strings.HasPrefix(name, "files/") && want(components, "files") {
			rel := strings.TrimPrefix(name, "files/")
			out := filepath.Join(stage, "files", rel)
			if !strings.HasPrefix(out, filepath.Join(stage, "files")+string(os.PathSeparator)) {
				return errors.New("backup file escapes stage")
			}
			if h.Typeflag == tar.TypeDir {
				if e = os.MkdirAll(out, 0750); e != nil {
					return e
				}
			} else {
				if e = os.MkdirAll(filepath.Dir(out), 0750); e != nil {
					return e
				}
				of, e := os.OpenFile(out, os.O_CREATE|os.O_EXCL|os.O_WRONLY, fs.FileMode(h.Mode)&0777)
				if e != nil {
					return e
				}
				_, e = io.Copy(of, io.LimitReader(tr, h.Size))
				ce := of.Close()
				if e != nil {
					return e
				}
				if ce != nil {
					return ce
				}
			}
		}
		if strings.HasPrefix(name, "databases/") && want(components, "databases") {
			base := filepath.Base(name)
			out := filepath.Join(dbdir, base)
			if h.Typeflag != tar.TypeReg || !strings.HasSuffix(base, ".sql.gz") {
				return errors.New("invalid database backup entry")
			}
			of, e := os.OpenFile(out, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
			if e != nil {
				return e
			}
			_, e = io.Copy(of, io.LimitReader(tr, h.Size))
			ce := of.Close()
			if e != nil {
				return e
			}
			if ce != nil {
				return ce
			}
		}
	}
	if !manifestOK {
		return errors.New("backup manifest missing")
	}
	if want(components, "files") {
		newRoot := filepath.Join(stage, "files")
		if _, e = os.Stat(newRoot); e != nil {
			return errors.New("backup has no files component")
		}
		old := l.root + ".cpgw-pre-restore-" + randomArtifactID()
		if e = os.Rename(l.root, old); e != nil {
			return e
		}
		if e = os.Rename(newRoot, l.root); e != nil {
			_ = os.Rename(old, l.root)
			return e
		}
		_ = chownTree(l.root, uidFor(l.user), gidFor(l.user))
		_ = os.RemoveAll(old)
	}
	if want(components, "databases") {
		for _, name := range dbs {
			p := filepath.Join(dbdir, name+".sql.gz")
			if _, e = os.Stat(p); e != nil {
				return fmt.Errorf("backup missing database %s", name)
			}
			cmd := exec.CommandContext(ctx, "clpctl", "db:import", "--databaseName="+name, "--file="+p)
			if out, e := cmd.CombinedOutput(); e != nil {
				return fmt.Errorf("database restore %s failed: %s", name, redact(string(out)))
			}
		}
	}
	return nil
}
