package gateway

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	staticGetRouting    = "get_routing"
	staticUpdateRouting = "update_routing"
)

type StaticRequest struct {
	Operation       string `json:"operation"`
	Domain          string `json:"domain"`
	SPAFallback     bool   `json:"spa_fallback"`
	IfMatchRevision string `json:"if_match_revision,omitempty"`
}
type StaticSettings struct {
	Domain      string `json:"domain"`
	SPAFallback bool   `json:"spa_fallback"`
	Revision    string `json:"revision"`
}

func staticRevision(domain, content string, pepper []byte) string {
	h := hmac.New(sha256.New, pepper)
	_, _ = h.Write([]byte(domain + "\x00" + content))
	return "rev_" + base64.RawURLEncoding.EncodeToString(h.Sum(nil)[:18])
}

func executeStatic(ctx context.Context, c Config, s *State, r StaticRequest) (StaticSettings, error) {
	if err := ValidateDomain(r.Domain); err != nil {
		return StaticSettings{}, err
	}
	db, err := openCloudPanelDB(c.CloudPanelDatabase)
	if err != nil {
		return StaticSettings{}, err
	}
	defer db.Close()
	site, err := readCloudPanelSite(ctx, db, r.Domain)
	if err != nil {
		return StaticSettings{}, err
	}
	if site.Type != "static" {
		return StaticSettings{}, errors.New("static settings are only applicable to CloudPanel static sites")
	}
	path := filepath.Join("/etc/nginx/sites-enabled", r.Domain+".conf")
	content, err := os.ReadFile(path)
	if err != nil {
		return StaticSettings{}, errors.New("CloudPanel vhost not found")
	}
	settings := StaticSettings{Domain: r.Domain, SPAFallback: strings.Contains(string(content), "# cloudpanel-gateway-spa-fallback"), Revision: staticRevision(r.Domain, string(content), s.pepper)}
	if r.Operation == staticGetRouting {
		return settings, nil
	}
	if r.Operation != staticUpdateRouting {
		return StaticSettings{}, errors.New("unsupported static operation")
	}
	if r.IfMatchRevision == "" || !hmac.Equal([]byte(r.IfMatchRevision), []byte(settings.Revision)) {
		return StaticSettings{}, errors.New("settings revision conflict")
	}
	updated, err := patchSPAFallback(string(content), r.SPAFallback)
	if err != nil {
		return StaticSettings{}, err
	}
	if err = CallNginxCommit(ctx, c, r.Domain, updated); err != nil {
		return StaticSettings{}, err
	}
	return StaticSettings{Domain: r.Domain, SPAFallback: r.SPAFallback, Revision: staticRevision(r.Domain, updated, s.pepper)}, nil
}

func patchSPAFallback(vhost string, enable bool) (string, error) {
	const marker = "# cloudpanel-gateway-spa-fallback"
	if strings.Contains(vhost, marker) {
		start := strings.Index(vhost, marker)
		lineEnd := strings.Index(vhost[start:], "\n")
		if lineEnd < 0 {
			return "", errors.New("invalid managed SPA fallback block")
		}
		lineEnd += start + 1
		tryStart := lineEnd
		tryEnd := strings.Index(vhost[tryStart:], "\n")
		if tryEnd < 0 {
			return "", errors.New("invalid managed SPA fallback block")
		}
		tryEnd += tryStart + 1
		if enable {
			return vhost, nil
		}
		return vhost[:start] + vhost[tryEnd:], nil
	}
	if !enable {
		return vhost, nil
	}
	needle := "location / {"
	idx := strings.Index(vhost, needle)
	if idx < 0 {
		return "", errors.New("unsupported CloudPanel static vhost: location / block not found")
	}
	end := strings.Index(vhost[idx:], "}")
	if end < 0 {
		return "", errors.New("unsupported CloudPanel static vhost: malformed location block")
	}
	block := vhost[idx : idx+end]
	if strings.Contains(block, "try_files") {
		return "", errors.New("static vhost already has unmanaged try_files routing")
	}
	insert := idx + len(needle)
	return vhost[:insert] + "\n        " + marker + "\n        try_files $uri $uri/ /index.html;\n" + vhost[insert:], nil
}

var _ = time.Second
