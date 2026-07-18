package gateway

import (
	"archive/zip"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateNodeRequest(t *testing.T) {
	valid := NodeRequest{Domain: "app.example.com", Entrypoint: "dist/server.mjs", Args: []string{"--trace-warnings"}, AppPort: 3030, HealthPath: "/healthz"}
	if err := validateNodeRequest(valid); err != nil {
		t.Fatalf("valid request rejected: %v", err)
	}
	for _, r := range []NodeRequest{
		{Domain: "app.example.com", Entrypoint: "../server.js"},
		{Domain: "app.example.com", Entrypoint: "server.ts"},
		{Domain: "app.example.com", Entrypoint: "server.js", Args: []string{"--x=$(id)"}},
		{Domain: "app.example.com", Entrypoint: "server.js", AppPort: 80},
	} {
		if err := validateNodeRequest(r); err == nil {
			t.Fatalf("unsafe request accepted: %#v", r)
		}
	}
}

func TestInspectProjectArtifact(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "source.zip")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	z := zip.NewWriter(f)
	for name, contents := range map[string]string{"package.json": `{"dependencies":{"vite":"1"},"scripts":{"build":"vite build"}}`, "package-lock.json": "{}"} {
		w, e := z.Create(name)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = w.Write([]byte(contents)); e != nil {
			t.Fatal(e)
		}
	}
	if err = z.Close(); err != nil {
		t.Fatal(err)
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	got, err := inspectProject(Artifact{ID: "artifact_test", Path: path})
	if err != nil {
		t.Fatal(err)
	}
	if got.Framework != "vite" || !got.HasPackageLock || !strings.Contains(strings.Join(got.SupportedModes, ","), "static") {
		t.Fatalf("unexpected inspection: %#v", got)
	}
}

func TestPatchSPAFallback(t *testing.T) {
	before := "server {\nlocation / {\n    index index.html;\n}\n}\n"
	on, err := patchSPAFallback(before, true)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(on, "try_files $uri $uri/ /index.html;") {
		t.Fatalf("missing fallback: %s", on)
	}
	off, err := patchSPAFallback(on, false)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(off, "cloudpanel-gateway-spa-fallback") || strings.Contains(off, "try_files") {
		t.Fatalf("fallback not removed: %s", off)
	}
}

func TestMCPToolRegistrationHasObjectOutputSchemas(t *testing.T) {
	dir := t.TempDir()
	c := Config{Database: filepath.Join(dir, "state.db"), SecretFile: filepath.Join(dir, "pepper"), ArtifactDir: filepath.Join(dir, "artifacts")}
	s, err := OpenState(c, true)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	a := NewAPIServer(c, s, slog.Default())
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("MCP tool registration panicked: %v", r)
		}
	}()
	if a.newMCP(&Token{ID: "tok_test", Scopes: []string{"admin"}}) == nil {
		t.Fatal("MCP server is nil")
	}
}
