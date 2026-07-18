package gateway

import (
	"strings"
	"testing"
)

func TestPHPSettingsValidationAndPreservation(t *testing.T) {
	p := &cloudPanelPHP{MemoryLimit: "512M", MaxExecutionTime: "60", MaxInputTime: "60", MaxInputVars: "10000", PostMaxSize: "64M", UploadMaxFileSize: "64M", AdditionalConfiguration: "date.timezone=UTC;\nunknown.secret=value;\ndisplay_errors=off;"}
	values, additional, err := validatePHPUpdate(p, map[string]string{"memory_limit": "768M", "display_errors": "on", "session.cookie_samesite": "Lax"})
	if err != nil || values["memory_limit"] != "768M" || values["display_errors"] != "on" {
		t.Fatalf("valid update rejected: values=%v err=%v", values, err)
	}
	if additional == "" || values["session.cookie_samesite"] != "Lax" {
		t.Fatalf("safe directives not preserved: %q", additional)
	}
	if _, _, err := validatePHPUpdate(p, map[string]string{"auto_prepend_file": "/tmp/x"}); err == nil {
		t.Fatal("unsafe directive accepted")
	}
	if _, _, err := validatePHPUpdate(p, map[string]string{"upload_max_filesize": "128M"}); err == nil {
		t.Fatal("upload larger than post accepted")
	}
}

func TestPageSpeedNormalization(t *testing.T) {
	ps, config, err := normalizePageSpeed(&PageSpeedUpdate{Enabled: true, Preset: "core", EnableFilters: []string{"lazyload_images"}})
	if err != nil || !ps.Enabled || config == "" {
		t.Fatalf("valid PageSpeed settings rejected: %+v %v", ps, err)
	}
	if _, _, err := normalizePageSpeed(&PageSpeedUpdate{Enabled: true, Preset: "core", EnableFilters: []string{"not-a-filter"}}); err == nil {
		t.Fatal("unknown filter accepted")
	}
	if _, _, err := normalizePageSpeed(&PageSpeedUpdate{Enabled: true, Preset: "core", EnableFilters: []string{"lazyload_images"}, DisableFilters: []string{"lazyload_images"}}); err == nil {
		t.Fatal("conflicting filters accepted")
	}
}

func TestPageSpeedGlobalConfigIsNarrowAndIdempotent(t *testing.T) {
	input := "http {\n    pagespeed off;\n    pagespeed XHeaderValue 1;\n}\n"
	got, err := pageSpeedGlobalConfig(input)
	if err != nil || got == input || !containsAll(got, "pagespeed FileCachePath /var/cache/ngx_pagespeed;", "cloudpanel-gateway-pagespeed-global") {
		t.Fatalf("expected managed cache directive, got %q (err=%v)", got, err)
	}
	again, err := pageSpeedGlobalConfig(got)
	if err != nil || again != got {
		t.Fatalf("global config must be idempotent: %q (err=%v)", again, err)
	}
	if _, err := pageSpeedGlobalConfig("http { pagespeed FileCachePath /tmp/unsafe; }"); err == nil {
		t.Fatal("unmanaged cache path accepted")
	}
}

func containsAll(s string, values ...string) bool {
	for _, value := range values {
		if !strings.Contains(s, value) {
			return false
		}
	}
	return true
}

func TestSettingsRevisionConflicts(t *testing.T) {
	s := cloudPanelSite{Domain: "example.com", UpdatedAt: "2026-01-01 00:00:00", RootDirectory: "example.com", PageSpeedSettings: "", PHP: &cloudPanelPHP{Version: "8.3", MemoryLimit: "512M", MaxExecutionTime: "60", MaxInputTime: "60", MaxInputVars: "10000", PostMaxSize: "64M", UploadMaxFileSize: "64M"}}
	pepper := []byte("test-pepper")
	if err := verifyRevision(s, siteRevision(s, pepper), pepper); err != nil {
		t.Fatal(err)
	}
	before := siteRevision(s, pepper)
	s.PHP.MaxExecutionTime = "61"
	if before == siteRevision(s, pepper) {
		t.Fatal("PHP core limit did not change revision")
	}
	if err := verifyRevision(s, "rev_wrong", pepper); err == nil {
		t.Fatal("bad revision accepted")
	}
}
