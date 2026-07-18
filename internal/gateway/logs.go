package gateway

import (
	"bufio"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	defaultLogLines = 200
	maxLogLines     = 1000
	maxLogWindow    = 7 * 24 * time.Hour
	maxLogBytes     = int64(8 << 20)
)

type LogRequest struct {
	Domain      string   `json:"domain"`
	Sources     []string `json:"sources,omitempty"`
	AppLogPath  string   `json:"app_log_path,omitempty"`
	From        string   `json:"from,omitempty"`
	To          string   `json:"to,omitempty"`
	Contains    string   `json:"contains,omitempty"`
	Statuses    []int    `json:"statuses,omitempty"`
	MaxLines    int      `json:"max_lines,omitempty"`
	Raw         bool     `json:"raw,omitempty"`
	Symptom     string   `json:"symptom,omitempty"`
	ListSources bool     `json:"list_sources,omitempty"`
}

type LogSource struct {
	ID       string `json:"id"`
	Kind     string `json:"kind"`
	Path     string `json:"path"`
	Rotated  bool   `json:"rotated"`
	Size     int64  `json:"size"`
	Modified string `json:"modified"`
}

type LogLine struct {
	Source           string `json:"source"`
	Timestamp        string `json:"timestamp,omitempty"`
	TimestampUnknown bool   `json:"timestamp_unknown,omitempty"`
	Line             string `json:"line"`
}

type LogSignal struct {
	Category string `json:"category"`
	Count    int    `json:"count"`
	Sample   string `json:"sample"`
}

type LogResult struct {
	Domain          string      `json:"domain"`
	From            string      `json:"from"`
	To              string      `json:"to"`
	Sources         []LogSource `json:"sources"`
	Lines           []LogLine   `json:"lines"`
	Signals         []LogSignal `json:"signals,omitempty"`
	Redactions      int         `json:"redactions"`
	BytesRead       int64       `json:"bytes_read"`
	Truncated       bool        `json:"truncated"`
	Raw             bool        `json:"raw"`
	Symptom         string      `json:"symptom,omitempty"`
	DiagnosisNotice string      `json:"diagnosis_notice,omitempty"`
}

type LogSourcesResult struct {
	Domain  string      `json:"domain"`
	Sources []LogSource `json:"sources"`
}

type siteLayout struct {
	domain string
	root   string
	user   string
	logs   string
}

func siteLayoutFor(domain string) (siteLayout, error) {
	if err := ValidateDomain(domain); err != nil {
		return siteLayout{}, err
	}
	configPath := filepath.Join("/etc/nginx/sites-enabled", domain+".conf")
	b, err := os.ReadFile(configPath)
	if err != nil {
		return siteLayout{}, fmt.Errorf("site vhost not found")
	}
	matches := rootDirectiveRE.FindStringSubmatch(string(b))
	if len(matches) != 2 {
		return siteLayout{}, errors.New("site document root not found")
	}
	root, err := filepath.EvalSymlinks(matches[1])
	if err != nil {
		return siteLayout{}, fmt.Errorf("resolve site document root: %w", err)
	}
	root = filepath.Clean(root)
	parts := strings.Split(strings.TrimPrefix(root, "/"), string(os.PathSeparator))
	if len(parts) < 4 || parts[0] != "home" || !siteUserRE.MatchString(parts[1]) {
		return siteLayout{}, errors.New("site document root is outside the CloudPanel site boundary")
	}
	logs := filepath.Join("/home", parts[1], "logs")
	if info, err := os.Stat(logs); err != nil || !info.IsDir() {
		return siteLayout{}, errors.New("site log directory not found")
	}
	return siteLayout{domain: domain, root: root, user: parts[1], logs: logs}, nil
}

var (
	rootDirectiveRE = regexp.MustCompile(`(?m)^\s*root\s+([^;\s]+);`)
	siteUserRE      = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)
	nginxTimeRE     = regexp.MustCompile(`\[([0-9]{2}/[A-Za-z]{3}/[0-9]{4}:[0-9:]{8} [+-][0-9]{4})\]`)
	phpTimeRE       = regexp.MustCompile(`\[([0-9]{2}-[A-Za-z]{3}-[0-9]{4} [0-9:]{8} [A-Z]+)\]|\[([0-9]{4}-[0-9]{2}-[0-9]{2} [0-9:]{8})\]`)
	statusRE        = regexp.MustCompile(`"\s+([1-5][0-9]{2})\s+`)
)

func (q *LogRequest) normalize() (time.Time, time.Time, error) {
	if err := ValidateDomain(q.Domain); err != nil {
		return time.Time{}, time.Time{}, err
	}
	now := time.Now().UTC()
	to := now
	from := now.Add(-24 * time.Hour)
	var err error
	if q.To != "" {
		to, err = time.Parse(time.RFC3339, q.To)
		if err != nil {
			return time.Time{}, time.Time{}, errors.New("to must be RFC3339")
		}
	}
	if q.From != "" {
		from, err = time.Parse(time.RFC3339, q.From)
		if err != nil {
			return time.Time{}, time.Time{}, errors.New("from must be RFC3339")
		}
	}
	from, to = from.UTC(), to.UTC()
	if !to.After(from) || to.Sub(from) > maxLogWindow {
		return time.Time{}, time.Time{}, errors.New("log window must be positive and no longer than 7 days")
	}
	if q.MaxLines == 0 {
		q.MaxLines = defaultLogLines
	}
	if q.MaxLines < 1 || q.MaxLines > maxLogLines {
		return time.Time{}, time.Time{}, fmt.Errorf("max_lines must be between 1 and %d", maxLogLines)
	}
	if len(q.Contains) > 200 {
		return time.Time{}, time.Time{}, errors.New("contains filter is too long")
	}
	if len(q.Symptom) > 500 {
		return time.Time{}, time.Time{}, errors.New("symptom is too long")
	}
	if len(q.Statuses) > 20 {
		return time.Time{}, time.Time{}, errors.New("too many status filters")
	}
	for _, s := range q.Statuses {
		if s < 100 || s > 599 {
			return time.Time{}, time.Time{}, errors.New("invalid HTTP status filter")
		}
	}
	return from, to, nil
}

func listLogSources(q LogRequest) ([]LogSource, error) {
	layout, err := siteLayoutFor(q.Domain)
	if err != nil {
		return nil, err
	}
	return discoverSources(layout, q.AppLogPath)
}

func discoverSources(layout siteLayout, appPath string) ([]LogSource, error) {
	base := []struct{ id, kind, path, relative string }{
		{"nginx_access", "nginx_access", filepath.Join(layout.logs, "nginx", "access.log"), "nginx/access.log"},
		{"nginx_error", "nginx_error", filepath.Join(layout.logs, "nginx", "error.log"), "nginx/error.log"},
		{"php_error", "php_error", filepath.Join(layout.logs, "php", "error.log"), "php/error.log"},
	}
	var out []LogSource
	for _, item := range base {
		out = append(out, sourceMetadata(item.id, item.kind, item.path, item.relative)...)
	}
	for _, rel := range discoverAppPaths(layout.root) {
		path := filepath.Join(layout.root, rel)
		out = append(out, sourceMetadata("app:"+rel, "app", path, rel)...)
	}
	if appPath != "" {
		path, rel, err := resolveAppPath(layout.root, appPath)
		if err != nil {
			return nil, err
		}
		out = append(out, sourceMetadata("app:"+rel, "app", path, rel)...)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ID == out[j].ID {
			return out[i].Path < out[j].Path
		}
		return out[i].ID < out[j].ID
	})
	return uniqueSources(out), nil
}

func sourceMetadata(id, kind, path, relative string) []LogSource {
	files, _ := rotatedFiles(path)
	result := make([]LogSource, 0, len(files))
	for _, file := range files {
		info, err := os.Stat(file)
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		display := relative
		if file != path {
			display += strings.TrimPrefix(file, path)
		}
		result = append(result, LogSource{ID: id, Kind: kind, Path: display, Rotated: file != path, Size: info.Size(), Modified: info.ModTime().UTC().Format(time.RFC3339)})
	}
	return result
}

func uniqueSources(in []LogSource) []LogSource {
	seen := map[string]bool{}
	out := make([]LogSource, 0, len(in))
	for _, s := range in {
		key := s.ID + "|" + s.Path
		if !seen[key] {
			seen[key] = true
			out = append(out, s)
		}
	}
	return out
}

func discoverAppPaths(root string) []string {
	candidates := []string{"storage/logs", "var/log", "wp-content/debug.log", "logs"}
	var out []string
	for _, rel := range candidates {
		path, _, err := resolveAppPath(root, rel)
		if err != nil {
			continue
		}
		info, err := os.Stat(path)
		if err != nil {
			continue
		}
		if info.Mode().IsRegular() {
			out = append(out, rel)
			continue
		}
		if !info.IsDir() {
			continue
		}
		_ = filepath.WalkDir(path, func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			relative, err := filepath.Rel(root, p)
			if err != nil || strings.Count(relative, string(os.PathSeparator)) > 4 {
				return nil
			}
			if d.Type().IsRegular() && (strings.HasSuffix(strings.ToLower(p), ".log") || strings.HasSuffix(strings.ToLower(p), ".log.gz")) {
				out = append(out, relative)
			}
			return nil
		})
	}
	sort.Strings(out)
	return out
}

func resolveAppPath(root, requestPath string) (string, string, error) {
	if filepath.IsAbs(requestPath) {
		return "", "", errors.New("app_log_path must be relative to the site document root")
	}
	clean := filepath.Clean(requestPath)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(os.PathSeparator)) {
		return "", "", errors.New("app_log_path escapes the site document root")
	}
	base, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", "", err
	}
	resolved, err := filepath.EvalSymlinks(filepath.Join(base, clean))
	if err != nil {
		return "", "", errors.New("app log path not found")
	}
	if resolved != base && !strings.HasPrefix(resolved, base+string(os.PathSeparator)) {
		return "", "", errors.New("app_log_path escapes the site document root")
	}
	info, err := os.Stat(resolved)
	if err != nil || (!info.Mode().IsRegular() && !info.IsDir()) {
		return "", "", errors.New("app_log_path must be a regular log file or directory")
	}
	return resolved, clean, nil
}

func rotatedFiles(path string) ([]string, error) {
	dir := filepath.Dir(path)
	name := filepath.Base(path)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var files []string
	for _, e := range entries {
		if e.Name() == name || rotatedName(name, e.Name()) {
			files = append(files, filepath.Join(dir, e.Name()))
		}
	}
	sort.Slice(files, func(i, j int) bool { return rotationRank(files[i]) > rotationRank(files[j]) })
	return files, nil
}

func rotatedName(base, name string) bool {
	rest := strings.TrimPrefix(name, base+".")
	if rest == name {
		return false
	}
	rest = strings.TrimSuffix(rest, ".gz")
	_, err := strconv.Atoi(rest)
	return err == nil
}
func rotationRank(path string) int {
	n := filepath.Base(path)
	n = strings.TrimSuffix(n, ".gz")
	idx := strings.LastIndex(n, ".")
	if idx < 0 {
		return 0
	}
	v, _ := strconv.Atoi(n[idx+1:])
	return v
}

func readLogs(q LogRequest) (LogResult, error) {
	from, to, err := q.normalize()
	if err != nil {
		return LogResult{}, err
	}
	layout, err := siteLayoutFor(q.Domain)
	if err != nil {
		return LogResult{}, err
	}
	sources, err := discoverSources(layout, q.AppLogPath)
	if err != nil {
		return LogResult{}, err
	}
	requestedSources := append([]string(nil), q.Sources...)
	if q.AppLogPath != "" && len(requestedSources) == 0 {
		requestedSources = []string{"app:" + filepath.Clean(q.AppLogPath)}
	}
	selected := sourceSelection(requestedSources, sources)
	if len(selected) == 0 {
		return LogResult{}, errors.New("no selected log sources are available")
	}
	result := LogResult{Domain: q.Domain, From: from.Format(time.RFC3339), To: to.Format(time.RFC3339), Sources: selected, Raw: q.Raw, Symptom: q.Symptom}
	statusSet := map[int]bool{}
	for _, s := range q.Statuses {
		statusSet[s] = true
	}
	for _, source := range selected {
		base := sourceBase(layout, source)
		if base == "" {
			continue
		}
		for _, path := range filesForSource(base, source) {
			if result.BytesRead >= maxLogBytes {
				result.Truncated = true
				break
			}
			lines, read, truncated, err := readLogFile(path, source.ID, path == base, from, to, q.Contains, statusSet, q.Raw, maxLogBytes-result.BytesRead)
			if err != nil {
				continue
			}
			result.BytesRead += read
			result.Truncated = result.Truncated || truncated
			for _, line := range lines {
				result.Lines = append(result.Lines, line)
			}
		}
	}
	sort.SliceStable(result.Lines, func(i, j int) bool {
		if result.Lines[i].Timestamp == "" {
			return false
		}
		if result.Lines[j].Timestamp == "" {
			return true
		}
		return result.Lines[i].Timestamp < result.Lines[j].Timestamp
	})
	if len(result.Lines) > q.MaxLines {
		result.Lines = result.Lines[len(result.Lines)-q.MaxLines:]
		result.Truncated = true
	}
	if !q.Raw {
		result.Redactions = redactLogLines(result.Lines)
	}
	result.Signals = diagnoseLines(result.Lines)
	result.DiagnosisNotice = "Signals are deterministic evidence only; use the returned lines and site context before applying a separate, explicit fix."
	return result, nil
}

func sourceSelection(want []string, available []LogSource) []LogSource {
	if len(want) == 0 {
		want = []string{"nginx_access", "nginx_error", "php_error"}
	}
	set := map[string]bool{}
	for _, v := range want {
		set[v] = true
	}
	selected := map[string]LogSource{}
	for _, source := range available {
		if !set[source.ID] && !(set["app"] && source.Kind == "app") {
			continue
		}
		prior, ok := selected[source.ID]
		if !ok || (prior.Rotated && !source.Rotated) {
			selected[source.ID] = source
		}
	}
	out := make([]LogSource, 0, len(selected))
	for _, source := range selected {
		out = append(out, source)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
func sourceBase(layout siteLayout, source LogSource) string {
	switch source.Kind {
	case "nginx_access":
		return filepath.Join(layout.logs, "nginx", "access.log")
	case "nginx_error":
		return filepath.Join(layout.logs, "nginx", "error.log")
	case "php_error":
		return filepath.Join(layout.logs, "php", "error.log")
	case "app":
		if strings.HasPrefix(source.ID, "app:") {
			return filepath.Join(layout.root, strings.TrimPrefix(source.ID, "app:"))
		}
	}
	return ""
}
func filesForSource(base string, _ LogSource) []string { files, _ := rotatedFiles(base); return files }

func readLogFile(path, source string, current bool, from, to time.Time, contains string, statuses map[int]bool, raw bool, budget int64) ([]LogLine, int64, bool, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, 0, false, err
	}
	defer file.Close()
	var reader io.Reader = file
	var closer io.Closer
	if strings.HasSuffix(path, ".gz") {
		gz, e := gzip.NewReader(file)
		if e != nil {
			return nil, 0, false, e
		}
		reader = gz
		closer = gz
	}
	if closer != nil {
		defer closer.Close()
	}
	info, _ := file.Stat()
	offset := int64(0)
	if !strings.HasSuffix(path, ".gz") && info != nil && info.Size() > budget {
		offset = info.Size() - budget
		_, _ = file.Seek(offset, io.SeekStart)
		reader = file
	}
	limited := &io.LimitedReader{R: reader, N: budget}
	scanner := bufio.NewScanner(limited)
	scanner.Buffer(make([]byte, 64<<10), 1<<20)
	var lines []LogLine
	skip := offset > 0
	for scanner.Scan() {
		text := scanner.Text()
		if skip {
			skip = false
			continue
		}
		timestamp, known := parseLogTime(text)
		if known && (timestamp.Before(from) || timestamp.After(to)) {
			continue
		}
		if !known && !current {
			continue
		}
		if contains != "" && !strings.Contains(strings.ToLower(text), strings.ToLower(contains)) {
			continue
		}
		if len(statuses) > 0 {
			status, ok := parseStatus(text)
			if !ok || !statuses[status] {
				continue
			}
		}
		line := LogLine{Source: source, Line: text, TimestampUnknown: !known}
		if known {
			line.Timestamp = timestamp.UTC().Format(time.RFC3339)
		}
		lines = append(lines, line)
	}
	return lines, budget - limited.N, limited.N == 0, nil
}

func parseLogTime(line string) (time.Time, bool) {
	if m := nginxTimeRE.FindStringSubmatch(line); len(m) == 2 {
		v, e := time.Parse("02/Jan/2006:15:04:05 -0700", m[1])
		return v, e == nil
	}
	if m := phpTimeRE.FindStringSubmatch(line); len(m) == 3 {
		if m[1] != "" {
			v, e := time.Parse("02-Jan-2006 15:04:05 MST", m[1])
			return v, e == nil
		}
		v, e := time.ParseInLocation("2006-01-02 15:04:05", m[2], time.UTC)
		return v, e == nil
	}
	return time.Time{}, false
}
func parseStatus(line string) (int, bool) {
	m := statusRE.FindStringSubmatch(line)
	if len(m) != 2 {
		return 0, false
	}
	v, e := strconv.Atoi(m[1])
	return v, e == nil
}

var redactionRules = []*regexp.Regexp{regexp.MustCompile(`(?i)(authorization:\s*(?:bearer|basic)\s+)[^\s"']+`), regexp.MustCompile(`(?i)(cookie:\s*)[^\r\n]+`), regexp.MustCompile(`(?i)([?&][a-z0-9_.-]+)=([^&\s"']+)`), regexp.MustCompile(`(?i)((?:password|passwd|token|api[_-]?key|secret|private[_-]?key)\s*[=:]\s*)[^\s,;"']+`)}

func redactLogLines(lines []LogLine) int {
	count := 0
	for i := range lines {
		for _, r := range redactionRules {
			lines[i].Line = r.ReplaceAllStringFunc(lines[i].Line, func(match string) string {
				count++
				idx := strings.IndexAny(match, "=:")
				if strings.HasPrefix(strings.ToLower(match), "authorization:") {
					return "Authorization: [redacted]"
				}
				if strings.HasPrefix(strings.ToLower(match), "cookie:") {
					return "Cookie: [redacted]"
				}
				if idx >= 0 {
					return match[:idx+1] + "[redacted]"
				}
				return "[redacted]"
			})
		}
	}
	return count
}

func diagnoseLines(lines []LogLine) []LogSignal {
	rules := []struct {
		name  string
		match func(string) bool
	}{{"http_5xx", func(s string) bool { v, ok := parseStatus(s); return ok && v >= 500 }}, {"http_4xx", func(s string) bool { v, ok := parseStatus(s); return ok && v >= 400 && v < 500 }}, {"upstream_timeout", func(s string) bool {
		return strings.Contains(s, "upstream timed out") || strings.Contains(s, "connect() failed")
	}}, {"php_fatal", func(s string) bool { return strings.Contains(s, "PHP Fatal error") || strings.Contains(s, "Uncaught ") }}, {"php_memory_limit", func(s string) bool { return strings.Contains(s, "Allowed memory size") }}, {"php_timeout", func(s string) bool { return strings.Contains(s, "Maximum execution time") }}, {"permission_denied", func(s string) bool { return strings.Contains(strings.ToLower(s), "permission denied") }}, {"missing_file", func(s string) bool {
		return strings.Contains(strings.ToLower(s), "no such file") || strings.Contains(s, "Primary script unknown")
	}}, {"database_connection", func(s string) bool {
		l := strings.ToLower(s)
		return strings.Contains(l, "database connection") || strings.Contains(l, "sqlstate") || strings.Contains(l, "access denied for user")
	}}}
	var out []LogSignal
	for _, rule := range rules {
		sig := LogSignal{Category: rule.name}
		for _, line := range lines {
			if rule.match(line.Line) {
				sig.Count++
				if sig.Sample == "" {
					sig.Sample = line.Line
				}
			}
		}
		if sig.Count > 0 {
			out = append(out, sig)
		}
	}
	return out
}
