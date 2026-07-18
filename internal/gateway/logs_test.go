package gateway

import (
	"compress/gzip"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLogRequestNormalizesAndBoundsWindow(t *testing.T) {
	q := LogRequest{Domain: "example.com"}
	from, to, err := q.normalize()
	if err != nil {
		t.Fatal(err)
	}
	if q.MaxLines != defaultLogLines || to.Sub(from) < 23*time.Hour || to.Sub(from) > 25*time.Hour {
		t.Fatalf("unexpected default query: lines=%d window=%s", q.MaxLines, to.Sub(from))
	}
	q = LogRequest{Domain: "example.com", From: "2026-01-01T00:00:00Z", To: "2026-01-09T00:00:01Z"}
	if _, _, err := q.normalize(); err == nil {
		t.Fatal("accepted a window longer than seven days")
	}
}

func TestResolveAppPathRejectsTraversalAndSymlinkEscape(t *testing.T) {
	root := t.TempDir()
	inside := filepath.Join(root, "logs", "app.log")
	if err := os.MkdirAll(filepath.Dir(inside), 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(inside, []byte("line\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := resolveAppPath(root, "../outside.log"); err == nil {
		t.Fatal("accepted traversal")
	}
	outside := filepath.Join(t.TempDir(), "outside.log")
	if err := os.WriteFile(outside, []byte("secret\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "escape.log")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := resolveAppPath(root, "escape.log"); err == nil {
		t.Fatal("accepted symlink outside document root")
	}
	want, err := filepath.EvalSymlinks(inside)
	if err != nil {
		t.Fatal(err)
	}
	if got, rel, err := resolveAppPath(root, "logs/app.log"); err != nil || got != want || rel != "logs/app.log" {
		t.Fatalf("valid path rejected: path=%q rel=%q err=%v", got, rel, err)
	}
}

func TestReadLogFileGzipFilteringAndUnknownCurrentLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "access.log.gz")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(f)
	_, _ = gz.Write([]byte(`127.0.0.1 - - [01/Jan/2026:00:01:00 +0000] "GET /bad HTTP/1.1" 502 1` + "\n"))
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	from := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	to := from.Add(5 * time.Minute)
	lines, _, _, err := readLogFile(path, "nginx_access", false, from, to, "", map[int]bool{502: true}, false, 1<<20)
	if err != nil || len(lines) != 1 || lines[0].TimestampUnknown {
		t.Fatalf("gzip filtering failed: lines=%+v err=%v", lines, err)
	}
	plain := filepath.Join(dir, "error.log")
	if err := os.WriteFile(plain, []byte("unstructured application message\n"), 0600); err != nil {
		t.Fatal(err)
	}
	lines, _, _, err = readLogFile(plain, "nginx_error", true, from, to, "", nil, false, 1<<20)
	if err != nil || len(lines) != 1 || !lines[0].TimestampUnknown {
		t.Fatalf("current unknown timestamp handling failed: lines=%+v err=%v", lines, err)
	}
	lines, _, _, err = readLogFile(plain, "nginx_error", false, from, to, "", nil, false, 1<<20)
	if err != nil || len(lines) != 0 {
		t.Fatalf("rotated unknown timestamp handling failed: lines=%+v err=%v", lines, err)
	}
}

func TestLogRedactionAndDiagnosis(t *testing.T) {
	lines := []LogLine{
		{Line: `GET /?token=abc HTTP/1.1" 500 Authorization: Bearer abc Cookie: sid=abc`},
		{Line: `PHP Fatal error: Allowed memory size exhausted; SQLSTATE database connection failed`},
		{Line: `connect() failed (13: Permission denied) while connecting to upstream`},
	}
	if count := redactLogLines(lines); count < 3 {
		t.Fatalf("expected multiple redactions, got %d", count)
	}
	for _, needle := range []string{"abc", "sid="} {
		if strings.Contains(lines[0].Line, needle) {
			t.Fatalf("secret %q survived redaction: %s", needle, lines[0].Line)
		}
	}
	signals := diagnoseLines(lines)
	seen := map[string]bool{}
	for _, signal := range signals {
		seen[signal.Category] = true
	}
	for _, category := range []string{"http_5xx", "php_fatal", "php_memory_limit", "database_connection", "upstream_timeout", "permission_denied"} {
		if !seen[category] {
			t.Errorf("missing diagnosis category %s: %+v", category, signals)
		}
	}
}

func TestSourceSelectionUsesOneBasePerSource(t *testing.T) {
	available := []LogSource{{ID: "nginx_access", Path: "access.log.1", Rotated: true}, {ID: "nginx_access", Path: "access.log"}, {ID: "php_error", Path: "error.log"}}
	selected := sourceSelection([]string{"nginx_access"}, available)
	if len(selected) != 1 || selected[0].Rotated {
		t.Fatalf("did not select current source once: %+v", selected)
	}
}

func TestSiteLogHTTPScopesDenyUnscopedAndRawRequests(t *testing.T) {
	state, config := testState(t)
	server := NewAPIServer(config, state, slog.Default())
	request := httptest.NewRequest(http.MethodGet, "/v1/sites/example.com/logs/sources", nil)
	request = request.WithContext(context.WithValue(request.Context(), tokenContextKey{}, &Token{ID: "token", Scopes: []string{"sites:write"}}))
	recorder := httptest.NewRecorder()
	server.siteLogs(recorder, request)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("unscoped request status=%d want=%d", recorder.Code, http.StatusForbidden)
	}

	request = httptest.NewRequest(http.MethodPost, "/v1/sites/example.com/logs/query", strings.NewReader(`{"raw":true}`))
	request = request.WithContext(context.WithValue(request.Context(), tokenContextKey{}, &Token{ID: "token", Scopes: []string{"logs:read"}}))
	recorder = httptest.NewRecorder()
	server.siteLogs(recorder, request)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("non-admin raw request status=%d want=%d", recorder.Code, http.StatusForbidden)
	}
}
