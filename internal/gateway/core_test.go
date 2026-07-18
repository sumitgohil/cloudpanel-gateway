package gateway

import (
	"path/filepath"
	"testing"
)

func testState(t *testing.T) (*State, Config) {
	t.Helper()
	d := t.TempDir()
	c := Config{Database: filepath.Join(d, "state.db"), SecretFile: filepath.Join(d, "pepper"), ArtifactDir: filepath.Join(d, "artifacts")}
	s, err := OpenState(c, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, c
}

func TestTokenLifecycleDoesNotStorePlaintext(t *testing.T) {
	s, _ := testState(t)
	token, raw, err := s.CreateToken("test", []string{"sites:write"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := s.Authenticate(raw); err != nil || got.ID != token.ID {
		t.Fatalf("authenticate: got=%v err=%v", got, err)
	}
	if err := s.RevokeToken(token.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authenticate(raw); err == nil {
		t.Fatal("revoked token authenticated")
	}
	var digest string
	if err := s.DB.QueryRow(`SELECT hex(digest) FROM tokens WHERE id=?`, token.ID).Scan(&digest); err != nil {
		t.Fatal(err)
	}
	if digest == raw {
		t.Fatal("plaintext token was stored")
	}
}

func TestActionValidationRejectsUnknownArgumentsAndUnsafeFiles(t *testing.T) {
	_, c := testState(t)
	if _, err := ValidateAction("site.delete", map[string]string{"domainName": "example.com", "extra": "x"}, c.ArtifactDir); err == nil {
		t.Fatal("unknown argument accepted")
	}
	if _, err := ValidateAction("database.export", map[string]string{"databaseName": "db", "file": "/etc/passwd"}, c.ArtifactDir); err == nil {
		t.Fatal("unsafe path accepted")
	}
	if _, err := ValidateAction("site.create_reverse_proxy", map[string]string{"domainName": "example.com", "reverseProxyUrl": "http://127.0.0.1:9780", "siteUser": "site", "siteUserPassword": "secret"}, c.ArtifactDir); err != nil {
		t.Fatalf("valid action rejected: %v", err)
	}
}
