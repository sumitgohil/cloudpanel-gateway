package gateway

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	settingsGet          = "get"
	settingsUpdateRoot   = "update_root"
	settingsRotatePass   = "rotate_password"
	settingsGetPHP       = "get_php"
	settingsUpdatePHP    = "update_php"
	settingsGetPageSpeed = "get_pagespeed"
	settingsUpdatePS     = "update_pagespeed"
	settingsPurgePS      = "purge_pagespeed"
)

type SettingsRequest struct {
	Operation       string            `json:"operation"`
	Domain          string            `json:"domain"`
	IfMatchRevision string            `json:"if_match_revision,omitempty"`
	Confirm         bool              `json:"confirm,omitempty"`
	RootDirectory   string            `json:"root_directory,omitempty"`
	PHPValues       map[string]string `json:"php_values,omitempty"`
	PageSpeed       *PageSpeedUpdate  `json:"pagespeed,omitempty"`
}

type PageSpeedUpdate struct {
	Enabled        bool     `json:"enabled"`
	Preset         string   `json:"preset"`
	EnableFilters  []string `json:"enable_filters,omitempty"`
	DisableFilters []string `json:"disable_filters,omitempty"`
}

type TLSStatus struct {
	Configured bool   `json:"configured"`
	ExpiresAt  string `json:"expires_at,omitempty"`
	Issuer     string `json:"issuer,omitempty"`
	DaysLeft   int    `json:"days_left,omitempty"`
}

type SiteSettings struct {
	Domain        string    `json:"domain"`
	Type          string    `json:"type"`
	SiteUser      string    `json:"site_user"`
	RootDirectory string    `json:"root_directory"`
	PHPVersion    string    `json:"php_version,omitempty"`
	PageSpeed     PageSpeed `json:"pagespeed"`
	TLS           TLSStatus `json:"tls"`
	Revision      string    `json:"revision"`
	Drift         []string  `json:"drift,omitempty"`
}

type PHPSettings struct {
	Applicable      bool              `json:"applicable"`
	PHPVersion      string            `json:"php_version,omitempty"`
	Values          map[string]string `json:"values,omitempty"`
	UnsupportedKeys []string          `json:"unsupported_directive_keys,omitempty"`
	Revision        string            `json:"revision,omitempty"`
}

type PageSpeed struct {
	Available       bool     `json:"available"`
	Enabled         bool     `json:"enabled"`
	Preset          string   `json:"preset,omitempty"`
	EnabledFilters  []string `json:"enabled_filters,omitempty"`
	DisabledFilters []string `json:"disabled_filters,omitempty"`
	Revision        string   `json:"revision,omitempty"`
}

type PasswordRotation struct {
	SiteUser string `json:"site_user"`
	Password string `json:"password"`
}

type cloudPanelSite struct {
	ID                int64
	UpdatedAt         string
	Type              string
	Domain            string
	RootDirectory     string
	User              string
	PageSpeedEnabled  bool
	PageSpeedSettings string
	VhostTemplate     string
	PHP               *cloudPanelPHP
}

type cloudPanelPHP struct {
	ID                      int64
	Version                 string
	MemoryLimit             string
	MaxExecutionTime        string
	MaxInputTime            string
	MaxInputVars            string
	PostMaxSize             string
	UploadMaxFileSize       string
	AdditionalConfiguration string
}

var (
	settingsRootRE = regexp.MustCompile(`(?m)^(\s*root\s+)[^;]+;`)
	phpValueRE     = regexp.MustCompile(`(?s)(fastcgi_param\s+PHP_VALUE\s+")[^"]*(";)`)
	phpLineRE      = regexp.MustCompile(`^([A-Za-z][A-Za-z0-9_.-]*)=([^;]*);?$`)
)

var corePHPKeys = map[string]bool{
	"memory_limit": true, "max_execution_time": true, "max_input_time": true, "max_input_vars": true,
	"post_max_size": true, "upload_max_filesize": true,
}

var safePHPKeys = map[string]bool{
	"date.timezone": true, "display_errors": true, "log_errors": true, "error_reporting": true,
	"max_file_uploads": true, "realpath_cache_size": true, "realpath_cache_ttl": true,
	"session.cookie_lifetime": true, "session.cookie_secure": true, "session.cookie_httponly": true,
	"session.cookie_samesite": true, "session.gc_maxlifetime": true,
	"opcache.enable": true, "opcache.validate_timestamps": true, "opcache.revalidate_freq": true,
}

var pageSpeedFilterSet = map[string]bool{
	"remove_quotes": true, "prioritize_critical_css": true, "recompress_images": true,
	"responsive_images": true, "resize_images": true, "lazyload_images": true, "sprite_images": true,
	"insert_dns_prefetch": true, "hint_preload_subresources": true, "collapse_whitespace": true,
	"dedup_inlined_images": true, "inline_preview_images": true, "resize_mobile_images": true,
}

func executeSettings(ctx context.Context, c Config, state *State, request SettingsRequest) (any, error) {
	if err := ValidateDomain(request.Domain); err != nil {
		return nil, err
	}
	db, err := openCloudPanelDB(c.CloudPanelDatabase)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	site, err := readCloudPanelSite(ctx, db, request.Domain)
	if err != nil {
		return nil, err
	}
	switch request.Operation {
	case settingsGet:
		return buildSiteSettings(site, state.pepper)
	case settingsGetPHP:
		return buildPHPSettings(site, state.pepper), nil
	case settingsGetPageSpeed:
		return buildPageSpeed(site, state.pepper), nil
	case settingsUpdateRoot:
		if !request.Confirm {
			return nil, errors.New("root directory update requires confirm=true")
		}
		if err := verifyRevision(site, request.IfMatchRevision, state.pepper); err != nil {
			return nil, err
		}
		root, err := validateRootDirectory(site.User, request.RootDirectory)
		if err != nil {
			return nil, err
		}
		if err := mutateSite(ctx, c, db, site, func(tx *sql.Tx) error {
			_, err := tx.ExecContext(ctx, `UPDATE site SET root_directory=?, updated_at=? WHERE id=?`, root, nowDB(), site.ID)
			return err
		}, func(vhost string) (string, error) { return patchRoots(vhost, site.User, root), nil }); err != nil {
			return nil, err
		}
		updated, _ := readCloudPanelSite(ctx, db, site.Domain)
		return buildSiteSettings(updated, state.pepper)
	case settingsRotatePass:
		if !request.Confirm {
			return nil, errors.New("password rotation requires confirm=true")
		}
		if err := verifyRevision(site, request.IfMatchRevision, state.pepper); err != nil {
			return nil, err
		}
		password, err := newID("", 24)
		if err != nil {
			return nil, err
		}
		cmd := exec.CommandContext(ctx, "chpasswd")
		cmd.Stdin = strings.NewReader(site.User + ":" + password + "\n")
		if out, err := cmd.CombinedOutput(); err != nil {
			return nil, fmt.Errorf("rotate site user password: %s", redact(string(out)))
		}
		return PasswordRotation{SiteUser: site.User, Password: password}, nil
	case settingsUpdatePHP:
		if err := verifyRevision(site, request.IfMatchRevision, state.pepper); err != nil {
			return nil, err
		}
		if site.PHP == nil {
			return nil, errors.New("php settings are not applicable to this site type")
		}
		values, additional, err := validatePHPUpdate(site.PHP, request.PHPValues)
		if err != nil {
			return nil, err
		}
		if err := mutateSite(ctx, c, db, site, func(tx *sql.Tx) error {
			_, err := tx.ExecContext(ctx, `UPDATE php_settings SET memory_limit=?, max_execution_time=?, max_input_time=?, max_input_vars=?, post_max_size=?, upload_max_file_size=?, additional_configuration=?, updated_at=? WHERE id=?`, values["memory_limit"], values["max_execution_time"], values["max_input_time"], values["max_input_vars"], values["post_max_size"], values["upload_max_filesize"], additional, nowDB(), site.PHP.ID)
			if err == nil {
				_, err = tx.ExecContext(ctx, `UPDATE site SET updated_at=? WHERE id=?`, nowDB(), site.ID)
			}
			return err
		}, func(vhost string) (string, error) { return patchPHPValue(vhost, values, additional) }); err != nil {
			return nil, err
		}
		updated, _ := readCloudPanelSite(ctx, db, site.Domain)
		return buildPHPSettings(updated, state.pepper), nil
	case settingsUpdatePS:
		if err := verifyRevision(site, request.IfMatchRevision, state.pepper); err != nil {
			return nil, err
		}
		ps, config, err := normalizePageSpeed(request.PageSpeed)
		if err != nil {
			return nil, err
		}
		if !ps.Available {
			return nil, errors.New("pagespeed module is not available")
		}
		if err := mutateSiteWithPageSpeedPrerequisite(ctx, c, db, site, func(tx *sql.Tx) error {
			_, err := tx.ExecContext(ctx, `UPDATE site SET page_speed_enabled=?, page_speed_settings=?, updated_at=? WHERE id=?`, ps.Enabled, config, nowDB(), site.ID)
			return err
		}, func(vhost string) (string, error) { return patchPageSpeed(vhost, config, ps.Enabled), nil }); err != nil {
			return nil, err
		}
		updated, _ := readCloudPanelSite(ctx, db, site.Domain)
		return buildPageSpeed(updated, state.pepper), nil
	case settingsPurgePS:
		if !pageSpeedAvailable() {
			return nil, errors.New("pagespeed module is not available")
		}
		cache := filepath.Join("/home", site.User, "tmp", "pagespeed_cache")
		if !strings.HasPrefix(cache, filepath.Join("/home", site.User)+string(os.PathSeparator)) {
			return nil, errors.New("invalid pagespeed cache path")
		}
		if err := os.RemoveAll(cache); err != nil {
			return nil, err
		}
		return map[string]any{"purged": true, "site_user": site.User}, nil
	default:
		return nil, errors.New("unsupported settings operation")
	}
}

func openCloudPanelDB(path string) (*sql.DB, error) {
	if path == "" {
		return nil, errors.New("cloudpanel database path is not configured")
	}
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return nil, errors.New("CloudPanel database is unavailable")
	}
	db, err := sql.Open("sqlite", "file:"+path+"?mode=rw&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if err = checkCloudPanelSchema(db); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

func checkCloudPanelSchema(db *sql.DB) error {
	for _, table := range []string{"site", "php_settings"} {
		var found string
		if err := db.QueryRow(`SELECT name FROM sqlite_master WHERE type='table' AND name=?`, table).Scan(&found); err != nil {
			return errors.New("unsupported CloudPanel database schema")
		}
	}
	return nil
}

func readCloudPanelSite(ctx context.Context, db *sql.DB, domain string) (cloudPanelSite, error) {
	const query = `SELECT s.id,s.updated_at,s.type,s.domain_name,s.root_directory,s.user,s.page_speed_enabled,COALESCE(s.page_speed_settings,''),s.vhost_template,p.id,p.php_version,p.memory_limit,p.max_execution_time,p.max_input_time,p.max_input_vars,p.post_max_size,p.upload_max_file_size,COALESCE(p.additional_configuration,'') FROM site s LEFT JOIN php_settings p ON p.site_id=s.id WHERE s.domain_name=?`
	var s cloudPanelSite
	var phpID sql.NullInt64
	var p cloudPanelPHP
	var enabled int
	err := db.QueryRowContext(ctx, query, domain).Scan(&s.ID, &s.UpdatedAt, &s.Type, &s.Domain, &s.RootDirectory, &s.User, &enabled, &s.PageSpeedSettings, &s.VhostTemplate, &phpID, &p.Version, &p.MemoryLimit, &p.MaxExecutionTime, &p.MaxInputTime, &p.MaxInputVars, &p.PostMaxSize, &p.UploadMaxFileSize, &p.AdditionalConfiguration)
	if errors.Is(err, sql.ErrNoRows) {
		return s, errors.New("CloudPanel site not found")
	}
	if err != nil {
		return s, err
	}
	s.PageSpeedEnabled = enabled != 0
	if phpID.Valid {
		p.ID = phpID.Int64
		s.PHP = &p
	}
	return s, nil
}

func siteRevision(s cloudPanelSite, pepper []byte) string {
	h := hmac.New(sha256.New, pepper)
	_, _ = h.Write([]byte(strings.Join([]string{s.Domain, s.UpdatedAt, s.RootDirectory, s.PageSpeedSettings}, "\x00")))
	if s.PHP != nil {
		_, _ = h.Write([]byte(strings.Join([]string{s.PHP.Version, s.PHP.MemoryLimit, s.PHP.MaxExecutionTime, s.PHP.MaxInputTime, s.PHP.MaxInputVars, s.PHP.PostMaxSize, s.PHP.UploadMaxFileSize, s.PHP.AdditionalConfiguration}, "\x00")))
	}
	return "rev_" + base64.RawURLEncoding.EncodeToString(h.Sum(nil)[:18])
}
func verifyRevision(s cloudPanelSite, revision string, pepper []byte) error {
	if revision == "" {
		return errors.New("if_match_revision is required")
	}
	if !hmac.Equal([]byte(revision), []byte(siteRevision(s, pepper))) {
		return errors.New("settings revision conflict")
	}
	return nil
}
func nowDB() string { return time.Now().UTC().Format("2006-01-02 15:04:05") }

func buildSiteSettings(s cloudPanelSite, pepper []byte) (SiteSettings, error) {
	ps := buildPageSpeed(s, pepper)
	tls := readTLS(s.Domain)
	out := SiteSettings{Domain: s.Domain, Type: s.Type, SiteUser: s.User, RootDirectory: s.RootDirectory, PageSpeed: ps, TLS: tls, Revision: siteRevision(s, pepper)}
	if s.PHP != nil {
		out.PHPVersion = s.PHP.Version
	}
	v, err := os.ReadFile(filepath.Join("/etc/nginx/sites-enabled", s.Domain+".conf"))
	if err == nil {
		want := filepath.Join("/home", s.User, "htdocs", s.RootDirectory)
		if !strings.Contains(string(v), "root "+want+";") {
			out.Drift = append(out.Drift, "root_directory")
		}
		if s.PageSpeedEnabled && !strings.Contains(string(v), "# cloudpanel-gateway-pagespeed begin") {
			out.Drift = append(out.Drift, "pagespeed")
		}
	}
	return out, nil
}
func buildPHPSettings(s cloudPanelSite, pepper []byte) PHPSettings {
	if s.PHP == nil {
		return PHPSettings{Applicable: false}
	}
	values := map[string]string{"memory_limit": s.PHP.MemoryLimit, "max_execution_time": s.PHP.MaxExecutionTime, "max_input_time": s.PHP.MaxInputTime, "max_input_vars": s.PHP.MaxInputVars, "post_max_size": s.PHP.PostMaxSize, "upload_max_filesize": s.PHP.UploadMaxFileSize}
	additional, unknown := parseAdditional(s.PHP.AdditionalConfiguration)
	for k, v := range additional {
		if safePHPKeys[k] {
			values[k] = v
		}
	}
	return PHPSettings{Applicable: true, PHPVersion: s.PHP.Version, Values: values, UnsupportedKeys: unknown, Revision: siteRevision(s, pepper)}
}
func buildPageSpeed(s cloudPanelSite, pepper []byte) PageSpeed {
	enabled, disabled := parsePageSpeed(s.PageSpeedSettings)
	return PageSpeed{Available: pageSpeedAvailable(), Enabled: s.PageSpeedEnabled, Preset: detectPreset(enabled, disabled), EnabledFilters: enabled, DisabledFilters: disabled, Revision: siteRevision(s, pepper)}
}
func readTLS(domain string) TLSStatus {
	b, err := os.ReadFile(filepath.Join("/etc/nginx/ssl-certificates", domain+".crt"))
	if err != nil {
		return TLSStatus{}
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return TLSStatus{Configured: true}
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return TLSStatus{Configured: true}
	}
	return TLSStatus{Configured: true, ExpiresAt: cert.NotAfter.UTC().Format(time.RFC3339), Issuer: cert.Issuer.CommonName, DaysLeft: int(time.Until(cert.NotAfter).Hours() / 24)}
}
func pageSpeedAvailable() bool {
	_, err := os.Stat("/usr/lib/nginx/modules/ngx_pagespeed.so")
	return err == nil
}

func validateRootDirectory(userName, input string) (string, error) {
	if filepath.IsAbs(input) {
		return "", errors.New("root_directory must be relative")
	}
	clean := filepath.Clean(input)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(os.PathSeparator)) {
		return "", errors.New("root_directory escapes htdocs")
	}
	base := filepath.Join("/home", userName, "htdocs")
	resolvedBase, err := filepath.EvalSymlinks(base)
	if err != nil {
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(filepath.Join(resolvedBase, clean))
	if err != nil || !strings.HasPrefix(resolved, resolvedBase+string(os.PathSeparator)) {
		return "", errors.New("root_directory escapes htdocs")
	}
	info, err := os.Stat(resolved)
	if err != nil || !info.IsDir() {
		return "", errors.New("root_directory must be an existing directory")
	}
	account, err := user.Lookup(userName)
	if err != nil {
		return "", errors.New("site user cannot be verified")
	}
	uid, err := strconv.ParseUint(account.Uid, 10, 32)
	stat, ok := info.Sys().(*syscall.Stat_t)
	if err != nil || !ok || uint64(stat.Uid) != uid {
		return "", errors.New("root_directory ownership cannot be verified")
	}
	return filepath.ToSlash(clean), nil
}
func patchRoots(vhost, user, root string) string {
	return settingsRootRE.ReplaceAllString(vhost, "${1}"+filepath.Join("/home", user, "htdocs", root)+";")
}

func parseAdditional(raw string) (map[string]string, []string) {
	out := map[string]string{}
	seen := map[string]bool{}
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		m := phpLineRE.FindStringSubmatch(line)
		if len(m) != 3 {
			continue
		}
		if safePHPKeys[m[1]] {
			out[m[1]] = m[2]
		} else if !seen[m[1]] {
			seen[m[1]] = true
		}
	}
	var unknown []string
	for k := range seen {
		unknown = append(unknown, k)
	}
	sort.Strings(unknown)
	return out, unknown
}
func validatePHPUpdate(p *cloudPanelPHP, changes map[string]string) (map[string]string, string, error) {
	if len(changes) == 0 {
		return nil, "", errors.New("at least one PHP value is required")
	}
	values := buildPHPSettings(cloudPanelSite{PHP: p}, nil).Values
	additional, _ := parseAdditional(p.AdditionalConfiguration)
	for k, v := range changes {
		if !corePHPKeys[k] && !safePHPKeys[k] {
			return nil, "", fmt.Errorf("unsupported PHP directive %s", k)
		}
		if err := validatePHPValue(k, v); err != nil {
			return nil, "", err
		}
		values[k] = v
		if safePHPKeys[k] {
			additional[k] = v
		}
	}
	post, err := sizeBytes(values["post_max_size"])
	if err != nil {
		return nil, "", err
	}
	upload, err := sizeBytes(values["upload_max_filesize"])
	if err != nil || post < upload {
		return nil, "", errors.New("post_max_size must be at least upload_max_filesize")
	}
	lines := strings.Split(p.AdditionalConfiguration, "\n")
	known := map[string]bool{}
	for i, line := range lines {
		m := phpLineRE.FindStringSubmatch(strings.TrimSpace(line))
		if len(m) == 3 && safePHPKeys[m[1]] {
			lines[i] = m[1] + "=" + additional[m[1]] + ";"
			known[m[1]] = true
		}
	}
	for _, k := range sortedKeys(additional) {
		if !known[k] {
			lines = append(lines, k+"="+additional[k]+";")
		}
	}
	return values, strings.TrimSpace(strings.Join(lines, "\n")), nil
}
func validatePHPValue(key, value string) error {
	if len(value) == 0 || len(value) > 128 {
		return errors.New("invalid PHP value")
	}
	bools := map[string]bool{"display_errors": true, "log_errors": true, "session.cookie_secure": true, "session.cookie_httponly": true, "opcache.enable": true, "opcache.validate_timestamps": true}
	if bools[key] && (value != "on" && value != "off" && value != "1" && value != "0") {
		return fmt.Errorf("%s must be boolean", key)
	}
	if key == "date.timezone" {
		if _, err := time.LoadLocation(value); err != nil {
			return errors.New("invalid timezone")
		}
	}
	if key == "session.cookie_samesite" && value != "Lax" && value != "Strict" && value != "None" {
		return errors.New("invalid session.cookie_samesite")
	}
	if key == "error_reporting" && value != "all" && value != "production" && value != "none" {
		return errors.New("invalid error_reporting mode")
	}
	if key == "memory_limit" || key == "post_max_size" || key == "upload_max_filesize" || key == "realpath_cache_size" {
		bytes, err := sizeBytes(value)
		if err != nil || bytes < 1024 || bytes > 2<<30 {
			return fmt.Errorf("invalid bounded size for %s", key)
		}
	}
	ranges := map[string][2]int64{"max_execution_time": {1, 3600}, "max_input_time": {1, 3600}, "max_input_vars": {100, 50000}, "max_file_uploads": {1, 100}, "realpath_cache_ttl": {0, 86400}, "session.cookie_lifetime": {0, 31536000}, "session.gc_maxlifetime": {60, 31536000}, "opcache.revalidate_freq": {0, 3600}}
	if bounds, ok := ranges[key]; ok {
		n, err := strconv.ParseInt(value, 10, 64)
		if err != nil || n < bounds[0] || n > bounds[1] {
			return fmt.Errorf("invalid bounded value for %s", key)
		}
	}
	if strings.ContainsAny(value, "\n\r\"'`\\") {
		return errors.New("invalid PHP value")
	}
	return nil
}
func sizeBytes(value string) (int64, error) {
	m := regexp.MustCompile(`^([0-9]+)([KMG])$`).FindStringSubmatch(strings.ToUpper(value))
	if len(m) != 3 {
		return 0, errors.New("size must use K, M, or G")
	}
	n, _ := strconv.ParseInt(m[1], 10, 64)
	mult := int64(1)
	if m[2] == "K" {
		mult = 1 << 10
	}
	if m[2] == "M" {
		mult = 1 << 20
	}
	if m[2] == "G" {
		mult = 1 << 30
	}
	return n * mult, nil
}
func patchPHPValue(vhost string, values map[string]string, additional string) (string, error) {
	all := map[string]string{}
	for k, v := range values {
		all[k] = v
	}
	for k, v := range parseMap(additional) {
		if safePHPKeys[k] {
			all[k] = v
		}
	}
	keys := sortedKeys(all)
	var lines []string
	for _, k := range keys {
		v := all[k]
		if k == "error_reporting" {
			v = map[string]string{"all": "E_ALL", "production": "E_ALL & ~E_DEPRECATED & ~E_STRICT", "none": "0"}[v]
		}
		lines = append(lines, k+"="+v+";")
	}
	out := phpValueRE.ReplaceAllString(vhost, "${1}\n"+strings.Join(lines, "\n")+"${2}")
	if out == vhost {
		return "", errors.New("CloudPanel PHP_VALUE block not found")
	}
	return out, nil
}
func parseMap(raw string) map[string]string { m, _ := parseAdditional(raw); return m }
func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func normalizePageSpeed(in *PageSpeedUpdate) (PageSpeed, string, error) {
	if in == nil {
		return PageSpeed{}, "", errors.New("pagespeed settings are required")
	}
	if !in.Enabled {
		return PageSpeed{Available: pageSpeedAvailable(), Enabled: false}, "", nil
	}
	presets := map[string][]string{"core": {"remove_quotes", "collapse_whitespace", "dedup_inlined_images"}, "image": {"remove_quotes", "collapse_whitespace", "dedup_inlined_images", "recompress_images", "responsive_images", "resize_images", "lazyload_images", "sprite_images", "inline_preview_images", "resize_mobile_images"}, "cloudpanel-default": {"remove_quotes", "recompress_images", "responsive_images", "resize_images", "lazyload_images", "sprite_images", "insert_dns_prefetch", "hint_preload_subresources", "collapse_whitespace", "dedup_inlined_images", "inline_preview_images", "resize_mobile_images"}}
	filters, ok := presets[in.Preset]
	if !ok {
		return PageSpeed{}, "", errors.New("invalid pagespeed preset")
	}
	enabled := map[string]bool{}
	for _, f := range filters {
		enabled[f] = true
	}
	disabled := map[string]bool{}
	for _, f := range in.EnableFilters {
		if !pageSpeedFilterSet[f] {
			return PageSpeed{}, "", errors.New("unsupported pagespeed filter")
		}
		enabled[f] = true
	}
	for _, f := range in.DisableFilters {
		if !pageSpeedFilterSet[f] {
			return PageSpeed{}, "", errors.New("invalid pagespeed filter")
		}
		if contains(in.EnableFilters, f) {
			return PageSpeed{}, "", errors.New("pagespeed filter cannot be both enabled and disabled")
		}
		disabled[f] = true
		delete(enabled, f)
	}
	e := sortedSet(enabled)
	d := sortedSet(disabled)
	var b strings.Builder
	b.WriteString("pagespeed RewriteLevel CoreFilters;\n")
	for _, f := range e {
		b.WriteString("pagespeed EnableFilters " + f + ";\n")
	}
	for _, f := range d {
		b.WriteString("pagespeed DisableFilters " + f + ";\n")
	}
	b.WriteString("pagespeed HttpCacheCompressionLevel 0;\npagespeed FetchHttps enable;")
	return PageSpeed{Available: pageSpeedAvailable(), Enabled: true, Preset: in.Preset, EnabledFilters: e, DisabledFilters: d}, b.String(), nil
}
func sortedSet(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		if m[k] {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}
func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
func parsePageSpeed(raw string) ([]string, []string) {
	var e, d []string
	for _, line := range strings.Split(raw, "\n") {
		fields := strings.Fields(strings.TrimSuffix(strings.TrimSpace(line), ";"))
		if len(fields) == 3 && fields[0] == "pagespeed" {
			if fields[1] == "EnableFilters" {
				e = append(e, strings.Split(fields[2], ",")...)
			}
			if fields[1] == "DisableFilters" {
				d = append(d, strings.Split(fields[2], ",")...)
			}
		}
	}
	sort.Strings(e)
	sort.Strings(d)
	return e, d
}
func detectPreset(e, d []string) string {
	_ = d
	if len(e) == 0 {
		return "off"
	}
	return "custom"
}
func patchPageSpeed(vhost, config string, enabled bool) string {
	begin := "# cloudpanel-gateway-pagespeed begin"
	end := "# cloudpanel-gateway-pagespeed end"
	re := regexp.MustCompile(`(?s)\n?\s*# cloudpanel-gateway-pagespeed begin.*?# cloudpanel-gateway-pagespeed end\n?`)
	vhost = re.ReplaceAllString(vhost, "\n")
	if !enabled {
		return vhost
	}
	block := "\n  " + begin + "\n  pagespeed on;\n"
	for _, line := range strings.Split(config, "\n") {
		block += "  " + line + "\n"
	}
	block += "  " + end + "\n"
	idx := strings.Index(vhost, "\n\n  access_log")
	if idx < 0 {
		idx = strings.Index(vhost, "\n  location ")
	}
	if idx < 0 {
		return vhost
	}
	return vhost[:idx] + block + vhost[idx:]
}

func mutateSite(ctx context.Context, c Config, db *sql.DB, site cloudPanelSite, dbUpdate func(*sql.Tx) error, patch func(string) (string, error)) error {
	return mutateSiteWithCommit(ctx, c, db, site, dbUpdate, patch, func(ctx context.Context, before, after string) error {
		return CallNginxCommit(ctx, c, site.Domain, after)
	}, func(before string) {
		_ = CallNginxCommit(context.Background(), c, site.Domain, before)
	})
}

func mutateSiteWithPageSpeedPrerequisite(ctx context.Context, c Config, db *sql.DB, site cloudPanelSite, dbUpdate func(*sql.Tx) error, patch func(string) (string, error)) error {
	globalConfig, err := os.ReadFile("/etc/nginx/nginx.conf")
	if err != nil {
		return errors.New("nginx global configuration is unavailable")
	}
	globalAfter, err := pageSpeedGlobalConfig(string(globalConfig))
	if err != nil {
		return err
	}
	return mutateSiteWithCommit(ctx, c, db, site, dbUpdate, patch, func(ctx context.Context, before, after string) error {
		return CallNginxCommitWithPageSpeedPrerequisite(ctx, c, site.Domain, after, globalAfter)
	}, func(before string) {
		// The FileCachePath prerequisite is safe to retain; only the site vhost
		// is reverted if the subsequent database transaction cannot commit.
		_ = CallNginxCommit(context.Background(), c, site.Domain, before)
	})
}

func mutateSiteWithCommit(ctx context.Context, c Config, db *sql.DB, site cloudPanelSite, dbUpdate func(*sql.Tx) error, patch func(string) (string, error), commit func(context.Context, string, string) error, rollback func(string)) error {
	vhostPath := filepath.Join("/etc/nginx/sites-enabled", site.Domain+".conf")
	before, err := os.ReadFile(vhostPath)
	if err != nil {
		return errors.New("CloudPanel vhost not found")
	}
	after, err := patch(string(before))
	if err != nil {
		return err
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err = dbUpdate(tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	if err = commit(ctx, string(before), after); err != nil {
		_ = tx.Rollback()
		return err
	}
	if err = tx.Commit(); err != nil {
		rollback(string(before))
		return err
	}
	return nil
}

const pageSpeedCachePath = "/var/cache/ngx_pagespeed"

func pageSpeedGlobalConfig(current string) (string, error) {
	cacheRE := regexp.MustCompile(`(?m)^\s*pagespeed\s+FileCachePath\s+([^;]+);\s*$`)
	if match := cacheRE.FindStringSubmatch(current); len(match) == 2 {
		if strings.TrimSpace(match[1]) != pageSpeedCachePath {
			return "", errors.New("an unmanaged PageSpeed FileCachePath is already configured")
		}
		return current, nil
	}
	anchor := regexp.MustCompile(`(?m)^([ \t]*pagespeed\s+XHeaderValue\s+1;[^\n]*)$`)
	if !anchor.MatchString(current) {
		return "", errors.New("CloudPanel PageSpeed global configuration is not recognized")
	}
	return anchor.ReplaceAllString(current, "$1\n    # cloudpanel-gateway-pagespeed-global begin\n    pagespeed FileCachePath "+pageSpeedCachePath+";\n    # cloudpanel-gateway-pagespeed-global end"), nil
}

func ensurePageSpeedCachePath() error {
	info, err := os.Lstat(pageSpeedCachePath)
	if err == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("invalid PageSpeed cache directory")
		}
	} else if os.IsNotExist(err) {
		if err := os.Mkdir(pageSpeedCachePath, 0700); err != nil {
			return err
		}
	} else {
		return err
	}
	if err := os.Chmod(pageSpeedCachePath, 0700); err != nil {
		return err
	}
	return os.Chown(pageSpeedCachePath, 0, 0)
}
