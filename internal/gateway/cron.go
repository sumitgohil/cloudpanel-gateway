package gateway

// CloudPanel persists site cron jobs in SQLite and renders one /etc/cron.d
// file per site user.  This adapter keeps those two representations in sync
// without ever accepting a caller-supplied user, cron-file path, or shell
// command for typed runners.

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	cronList    = "list"
	cronCreate  = "create"
	cronUpdate  = "update"
	cronDelete  = "delete"
	maxCronJobs = 100
)

type CronRequest struct {
	Operation       string   `json:"operation"`
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

type CronJob struct {
	ID        int64  `json:"id"`
	Minute    string `json:"minute"`
	Hour      string `json:"hour"`
	Day       string `json:"day"`
	Month     string `json:"month"`
	Weekday   string `json:"weekday"`
	Runner    string `json:"runner"`
	Target    string `json:"target,omitempty"`
	Command   string `json:"command"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

type CronResult struct {
	Domain   string    `json:"domain"`
	Jobs     []CronJob `json:"jobs"`
	Job      *CronJob  `json:"job,omitempty"`
	Revision string    `json:"revision"`
}

type cronSite struct {
	ID                       int64
	Domain, User, Root, Type string
}

func executeCron(ctx context.Context, c Config, s *State, r CronRequest) (CronResult, error) {
	if err := ValidateDomain(r.Domain); err != nil {
		return CronResult{}, err
	}
	db, err := openCloudPanelDB(c.CloudPanelDatabase)
	if err != nil {
		return CronResult{}, err
	}
	defer db.Close()
	site, err := cronSiteFor(ctx, db, r.Domain)
	if err != nil {
		return CronResult{}, err
	}
	if r.Operation == cronList {
		return readCronResult(ctx, db, s, r.Domain, site.ID)
	}
	if r.Operation != cronCreate && r.Operation != cronUpdate && r.Operation != cronDelete {
		return CronResult{}, errors.New("unsupported cron operation")
	}
	before, err := readCronResult(ctx, db, s, r.Domain, site.ID)
	if err != nil {
		return CronResult{}, err
	}
	if r.IfMatchRevision == "" || !hmac.Equal([]byte(r.IfMatchRevision), []byte(before.Revision)) {
		return CronResult{}, errors.New("cron revision conflict")
	}
	if r.Operation == cronDelete && !r.Confirm {
		return CronResult{}, errors.New("cron deletion requires confirm=true")
	}
	if r.Operation != cronDelete {
		if err := validateCronSchedule(r); err != nil {
			return CronResult{}, err
		}
		if err := validateCronRunner(ctx, c, s, db, site, &r); err != nil {
			return CronResult{}, err
		}
	}
	var command string
	if r.Operation != cronDelete {
		command, err = renderCronCommand(ctx, c, db, site, r)
		if err != nil {
			return CronResult{}, err
		}
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return CronResult{}, err
	}
	defer tx.Rollback()
	now := time.Now().UTC().Format("2006-01-02 15:04:05")
	var jobID int64
	metadataDelete := false
	switch r.Operation {
	case cronCreate:
		var n int
		if err = tx.QueryRowContext(ctx, `SELECT COUNT(1) FROM cron_job WHERE site_id=?`, site.ID).Scan(&n); err != nil {
			return CronResult{}, err
		}
		if n >= maxCronJobs {
			return CronResult{}, fmt.Errorf("site cron job limit (%d) reached", maxCronJobs)
		}
		result, e := tx.ExecContext(ctx, `INSERT INTO cron_job(site_id,created_at,updated_at,minute,hour,day,month,weekday,command) VALUES(?,?,?,?,?,?,?,?,?)`, site.ID, now, now, r.Minute, r.Hour, r.Day, r.Month, r.Weekday, command)
		if e != nil {
			return CronResult{}, e
		}
		jobID, _ = result.LastInsertId()
	case cronUpdate:
		if r.JobID < 1 {
			return CronResult{}, errors.New("invalid cron job ID")
		}
		result, e := tx.ExecContext(ctx, `UPDATE cron_job SET updated_at=?,minute=?,hour=?,day=?,month=?,weekday=?,command=? WHERE id=? AND site_id=?`, now, r.Minute, r.Hour, r.Day, r.Month, r.Weekday, command, r.JobID, site.ID)
		if e != nil {
			return CronResult{}, e
		}
		changed, _ := result.RowsAffected()
		if changed != 1 {
			return CronResult{}, errors.New("cron job not found")
		}
		jobID = r.JobID
	case cronDelete:
		if r.JobID < 1 {
			return CronResult{}, errors.New("invalid cron job ID")
		}
		result, e := tx.ExecContext(ctx, `DELETE FROM cron_job WHERE id=? AND site_id=?`, r.JobID, site.ID)
		if e != nil {
			return CronResult{}, e
		}
		changed, _ := result.RowsAffected()
		if changed != 1 {
			return CronResult{}, errors.New("cron job not found")
		}
		jobID = r.JobID
		metadataDelete = true
	}
	jobs, err := cronJobsForUser(ctx, tx, site.User)
	if err != nil {
		return CronResult{}, err
	}
	previous, existed, err := readSafeCronFile(filepath.Join(c.CronDir, site.User))
	if err != nil {
		return CronResult{}, err
	}
	if err = writeCronFile(c.CronDir, site.User, renderCronFile(jobs)); err != nil {
		return CronResult{}, err
	}
	if err = tx.Commit(); err != nil {
		_ = restoreCronFile(filepath.Join(c.CronDir, site.User), previous, existed)
		return CronResult{}, err
	}
	if metadataDelete {
		_, _ = s.DB.Exec(`DELETE FROM cron_metadata WHERE job_id=?`, jobID)
	} else {
		_, _ = s.DB.Exec(`INSERT INTO cron_metadata(job_id,domain,runner,target,updated_at) VALUES(?,?,?,?,?) ON CONFLICT(job_id) DO UPDATE SET domain=excluded.domain,runner=excluded.runner,target=excluded.target,updated_at=excluded.updated_at`, jobID, r.Domain, r.Runner, cronTarget(r), time.Now().UTC().Format(time.RFC3339))
	}
	after, err := readCronResult(ctx, db, s, r.Domain, site.ID)
	if err != nil {
		return CronResult{}, err
	}
	for i := range after.Jobs {
		if after.Jobs[i].ID == jobID {
			after.Job = &after.Jobs[i]
			break
		}
	}
	return after, nil
}

func cronSiteFor(ctx context.Context, db *sql.DB, domain string) (cronSite, error) {
	var s cronSite
	err := db.QueryRowContext(ctx, `SELECT id,domain_name,user,root_directory,type FROM site WHERE domain_name=?`, domain).Scan(&s.ID, &s.Domain, &s.User, &s.Root, &s.Type)
	if errors.Is(err, sql.ErrNoRows) {
		return s, errors.New("CloudPanel site not found")
	}
	if err != nil || !siteUserRE.MatchString(s.User) || s.Root == "" {
		return s, errors.New("unsupported CloudPanel cron schema or site")
	}
	return s, nil
}

func readCronResult(ctx context.Context, db *sql.DB, s *State, domain string, siteID int64) (CronResult, error) {
	rows, err := db.QueryContext(ctx, `SELECT id,minute,hour,day,month,weekday,command,created_at,updated_at FROM cron_job WHERE site_id=? ORDER BY id`, siteID)
	if err != nil {
		return CronResult{}, err
	}
	defer rows.Close()
	out := CronResult{Domain: domain, Jobs: []CronJob{}}
	for rows.Next() {
		var j CronJob
		if err = rows.Scan(&j.ID, &j.Minute, &j.Hour, &j.Day, &j.Month, &j.Weekday, &j.Command, &j.CreatedAt, &j.UpdatedAt); err != nil {
			return out, err
		}
		_ = s.DB.QueryRow(`SELECT runner,target FROM cron_metadata WHERE job_id=? AND domain=?`, j.ID, domain).Scan(&j.Runner, &j.Target)
		if j.Runner == "" {
			j.Runner = "raw_command"
			j.Command = "raw_command (redacted)"
		} else {
			j.Command = j.Runner + ": " + j.Target
		}
		out.Jobs = append(out.Jobs, j)
	}
	if err = rows.Err(); err != nil {
		return out, err
	}
	out.Revision = cronRevision(domain, out.Jobs, s.pepper)
	return out, nil
}

func cronRevision(domain string, jobs []CronJob, pepper []byte) string {
	h := hmac.New(sha256.New, pepper)
	_, _ = h.Write([]byte(domain))
	for _, j := range jobs {
		_, _ = h.Write([]byte(fmt.Sprintf("\x00%d\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s", j.ID, j.Minute, j.Hour, j.Day, j.Month, j.Weekday, j.UpdatedAt)))
	}
	return "rev_" + base64.RawURLEncoding.EncodeToString(h.Sum(nil)[:18])
}

func validateCronSchedule(r CronRequest) error {
	for _, v := range []struct {
		value    string
		min, max int
	}{{r.Minute, 0, 59}, {r.Hour, 0, 23}, {r.Day, 1, 31}, {r.Month, 1, 12}, {r.Weekday, 0, 7}} {
		if !validCronField(v.value, v.min, v.max) {
			return errors.New("invalid five-field cron schedule")
		}
	}
	return nil
}
func validCronField(v string, min, max int) bool {
	if v == "" || len(v) > 16 || strings.ContainsAny(v, " \t\r\n@") {
		return false
	}
	for _, item := range strings.Split(v, ",") {
		base := item
		if strings.Count(item, "/") > 1 {
			return false
		}
		if strings.Contains(item, "/") {
			p := strings.Split(item, "/")
			if len(p) != 2 || !validCronNumber(p[1], 1, max-min+1) {
				return false
			}
			base = p[0]
		}
		if base == "*" {
			continue
		}
		if strings.Count(base, "-") > 1 {
			return false
		}
		if strings.Contains(base, "-") {
			p := strings.Split(base, "-")
			if len(p) != 2 || !validCronNumber(p[0], min, max) || !validCronNumber(p[1], min, max) {
				return false
			}
			a, _ := strconv.Atoi(p[0])
			b, _ := strconv.Atoi(p[1])
			if a > b {
				return false
			}
			continue
		}
		if !validCronNumber(base, min, max) {
			return false
		}
	}
	return true
}
func validCronNumber(v string, min, max int) bool {
	if v == "" || len(v) > 2 {
		return false
	}
	n, e := strconv.Atoi(v)
	return e == nil && n >= min && n <= max
}

func validateCronRunner(ctx context.Context, c Config, s *State, db *sql.DB, site cronSite, r *CronRequest) error {
	if len(r.Args) > 16 {
		return errors.New("too many cron arguments")
	}
	for _, a := range r.Args {
		if len(a) == 0 || len(a) > 128 || strings.ContainsAny(a, "\x00\r\n") {
			return errors.New("invalid cron argument")
		}
	}
	switch r.Runner {
	case "php_script", "site_executable":
		p, err := siteRootFile(site, r.Target)
		if err != nil {
			return err
		}
		info, err := os.Stat(p)
		if err != nil || !info.Mode().IsRegular() {
			return errors.New("cron target is not a regular file")
		}
		if r.Runner == "site_executable" && info.Mode()&0111 == 0 {
			return errors.New("site executable target is not executable")
		}
	case "node_script":
		if r.Target == "" || filepath.IsAbs(r.Target) || strings.Contains(r.Target, "..") {
			return errors.New("invalid Node.js cron target")
		}
		p := filepath.Join("/home", site.User, "apps", site.Domain, "current", filepath.Clean(r.Target))
		info, err := os.Stat(p)
		if err != nil || !info.Mode().IsRegular() {
			return errors.New("managed Node.js release target not found")
		}
		version, _, err := cloudPanelNodeSettings(ctx, c, site.Domain)
		if err != nil {
			return err
		}
		if _, err = nodeBinaryForUser(site.User, version); err != nil {
			return err
		}
	case "http_request":
		if len(r.Args) != 0 {
			return errors.New("HTTP cron runner does not accept arguments")
		}
		if r.Method != "GET" && r.Method != "POST" {
			return errors.New("HTTP cron runner supports GET or POST only")
		}
		u, err := url.Parse(r.URL)
		if r.URL == "" || len(r.URL) > 180 || err != nil || u.Scheme != "https" || u.User != nil || u.Hostname() != site.Domain {
			return errors.New("HTTP cron URL must be HTTPS on the site domain")
		}
	case "raw_command":
		allowed, _ := s.Allowed("cron.raw_command")
		if !allowed {
			return errors.New("operation disabled by server policy")
		}
		if !r.Confirm {
			return errors.New("raw cron command requires confirm=true")
		}
		if len(r.RawCommand) == 0 || len(r.RawCommand) > 255 || strings.ContainsAny(r.RawCommand, "\x00\r\n%") {
			return errors.New("invalid raw cron command")
		}
	default:
		return errors.New("unsupported cron runner")
	}
	return nil
}

func siteRootFile(site cronSite, target string) (string, error) {
	if target == "" || filepath.IsAbs(target) || strings.Contains(target, "..") {
		return "", errors.New("invalid site-root-relative cron target")
	}
	base := filepath.Join("/home", site.User, "htdocs", site.Root)
	p := filepath.Join(base, filepath.Clean(target))
	real, err := filepath.EvalSymlinks(p)
	if err != nil || !strings.HasPrefix(real, base+string(os.PathSeparator)) {
		return "", errors.New("cron target escapes site document root")
	}
	return real, nil
}
func cronTarget(r CronRequest) string {
	if r.Runner == "http_request" {
		return r.URL
	}
	if r.Runner == "raw_command" {
		return ""
	}
	return r.Target
}
func shellQuote(v string) string { return "'" + strings.ReplaceAll(v, "'", "'\\''") + "'" }
func renderCronCommand(ctx context.Context, c Config, db *sql.DB, site cronSite, r CronRequest) (string, error) {
	args := make([]string, 0, len(r.Args))
	for _, a := range r.Args {
		args = append(args, shellQuote(a))
	}
	var command string
	switch r.Runner {
	case "php_script":
		var version string
		if err := db.QueryRowContext(ctx, `SELECT p.php_version FROM site s JOIN php_settings p ON p.site_id=s.id WHERE s.id=?`, site.ID).Scan(&version); err != nil || version == "" {
			return "", errors.New("CloudPanel PHP runtime is unavailable")
		}
		p, e := siteRootFile(site, r.Target)
		if e != nil {
			return "", e
		}
		command = shellQuote("/usr/bin/php"+version) + " " + shellQuote(p)
	case "site_executable":
		p, e := siteRootFile(site, r.Target)
		if e != nil {
			return "", e
		}
		command = shellQuote(p)
	case "node_script":
		version, _, e := cloudPanelNodeSettings(ctx, c, site.Domain)
		if e != nil {
			return "", e
		}
		bin, e := nodeBinaryForUser(site.User, version)
		if e != nil {
			return "", e
		}
		command = shellQuote(bin) + " " + shellQuote(filepath.Join("/home", site.User, "apps", site.Domain, "current", filepath.Clean(r.Target)))
	case "http_request":
		command = "/usr/bin/curl --fail --silent --show-error --max-time 60 -X " + r.Method + " " + shellQuote(r.URL)
	case "raw_command":
		command = r.RawCommand
	}
	if len(args) > 0 {
		command += " " + strings.Join(args, " ")
	}
	if len(command) > 255 {
		return "", errors.New("cron command exceeds CloudPanel 255-character limit")
	}
	return command, nil
}

type cronLine struct{ Minute, Hour, Day, Month, Weekday, User, Command string }

func cronJobsForUser(ctx context.Context, tx *sql.Tx, user string) ([]cronLine, error) {
	rows, e := tx.QueryContext(ctx, `SELECT c.minute,c.hour,c.day,c.month,c.weekday,s.user,c.command FROM cron_job c JOIN site s ON s.id=c.site_id WHERE s.user=? ORDER BY c.id`, user)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	var out []cronLine
	for rows.Next() {
		var l cronLine
		if e = rows.Scan(&l.Minute, &l.Hour, &l.Day, &l.Month, &l.Weekday, &l.User, &l.Command); e != nil {
			return nil, e
		}
		out = append(out, l)
	}
	return out, rows.Err()
}
func renderCronFile(lines []cronLine) []byte {
	var b strings.Builder
	b.WriteString("MAILTO=\"\"\n")
	for _, l := range lines {
		fmt.Fprintf(&b, "%s %s %s %s %s %s %s\n", l.Minute, l.Hour, l.Day, l.Month, l.Weekday, l.User, l.Command)
	}
	return []byte(b.String())
}
func readSafeCronFile(path string) ([]byte, bool, error) {
	info, e := os.Lstat(path)
	if errors.Is(e, os.ErrNotExist) {
		return nil, false, nil
	}
	if e != nil {
		return nil, false, e
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || !ok || stat.Uid != 0 {
		return nil, false, errors.New("managed cron file is unsafe")
	}
	b, e := os.ReadFile(path)
	return b, true, e
}
func writeCronFile(dir, user string, content []byte) error {
	if !siteUserRE.MatchString(user) {
		return errors.New("invalid site user")
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	path := filepath.Join(dir, user)
	if _, _, err := readSafeCronFile(path); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".cloudpanel-gateway-cron-")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if _, err = f.Write(content); err == nil {
		err = f.Chmod(0644)
	}
	if err == nil {
		err = f.Chown(0, 0)
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(name, path)
}
func restoreCronFile(path string, content []byte, existed bool) error {
	if !existed {
		return os.Remove(path)
	}
	return os.WriteFile(path, content, 0644)
}
