package gateway

import (
	"archive/zip"
	"bytes"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeTestZIP(t *testing.T, path string, entries map[string]string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	z := zip.NewWriter(f)
	for name, body := range entries {
		w, err := z.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = w.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err = z.Close(); err != nil {
		t.Fatal(err)
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestChunkedArtifactUploadOwnershipAndCompletion(t *testing.T) {
	dir := t.TempDir()
	c := Config{Database: filepath.Join(dir, "state.db"), SecretFile: filepath.Join(dir, "pepper"), ArtifactDir: filepath.Join(dir, "artifacts")}
	s, err := OpenState(c, true)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	a := &APIServer{Config: c, State: s}
	owner := &Token{ID: "tok_owner"}
	other := &Token{ID: "tok_other"}
	zipPath := filepath.Join(dir, "artifact.zip")
	writeTestZIP(t, zipPath, map[string]string{"index.php": "<?php echo 'safe';"})
	data, err := os.ReadFile(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	u, err := a.beginArtifactUpload(owner, 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = a.appendArtifactChunk(other, u.ID, 0, data); err == nil {
		t.Fatal("expected cross-token upload to be denied")
	}
	if _, err = a.appendArtifactChunk(owner, u.ID, 0, data); err != nil {
		t.Fatal(err)
	}
	artifact, err := a.completeArtifactUpload(owner, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if artifact.ID == "" || artifact.Size != int64(len(data)) {
		t.Fatalf("bad artifact: %#v", artifact)
	}
	if _, err = os.Stat(artifact.Path); err != nil {
		t.Fatal(err)
	}
	if !artifact.ExpiresAt.After(time.Now()) {
		t.Fatal("artifact should expire in the future")
	}
}

func TestExtractZIPRejectsTraversal(t *testing.T) {
	dir := t.TempDir()
	archive := filepath.Join(dir, "bad.zip")
	writeTestZIP(t, archive, map[string]string{"../outside": "no"})
	if _, err := extractZIP(archive, filepath.Join(dir, "out")); err == nil {
		t.Fatal("expected traversal ZIP to be rejected")
	}
}

func TestExtractZIPExtractsRegularFiles(t *testing.T) {
	dir := t.TempDir()
	archive := filepath.Join(dir, "ok.zip")
	out := filepath.Join(dir, "out")
	writeTestZIP(t, archive, map[string]string{"public/index.html": "safe"})
	if err := os.Mkdir(out, 0700); err != nil {
		t.Fatal(err)
	}
	n, err := extractZIP(archive, out)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("files=%d", n)
	}
	b, err := os.ReadFile(filepath.Join(out, "public", "index.html"))
	if err != nil || string(b) != "safe" {
		t.Fatalf("unexpected deployed content %q %v", b, err)
	}
}

func TestEncryptedBackupRoundTripAndTamper(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "in")
	encrypted := filepath.Join(dir, "backup.cpgb")
	out := filepath.Join(dir, "out")
	plain := bytes.Repeat([]byte("cloudpanel-gateway\n"), 300000)
	if err := os.WriteFile(in, plain, 0600); err != nil {
		t.Fatal(err)
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	digest, _, err := encryptFile(key, in, encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if err = decryptFile(key, encrypted, out, digest); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(out)
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("round trip mismatch: %v", err)
	}
	b, err := os.ReadFile(encrypted)
	if err != nil {
		t.Fatal(err)
	}
	b[len(b)-1] ^= 1
	if err = os.WriteFile(encrypted, b, 0600); err != nil {
		t.Fatal(err)
	}
	if err = decryptFile(key, encrypted, filepath.Join(dir, "tampered"), digest); err == nil {
		t.Fatal("expected tampered backup to be rejected")
	}
}
