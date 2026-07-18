package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// NginxCommitRequest is intentionally narrow: it can replace only the vhost
// selected by a validated CloudPanel domain, then validate and reload Nginx.
// It is accepted only over a root-only local socket.
type NginxCommitRequest struct {
	Version                  int    `json:"version"`
	Domain                   string `json:"domain"`
	Content                  string `json:"content"`
	GlobalContent            string `json:"global_content,omitempty"`
	EnsurePageSpeedCachePath bool   `json:"ensure_pagespeed_cache_path,omitempty"`
}
type NginxCommitResponse struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

func ListenNginxCommit(ctx context.Context, c Config) error {
	if err := os.MkdirAll(filepath.Dir(c.NginxCommitSocket), 0755); err != nil {
		return err
	}
	_ = os.Remove(c.NginxCommitSocket)
	ln, err := net.Listen("unix", c.NginxCommitSocket)
	if err != nil {
		return err
	}
	defer ln.Close()
	if err = os.Chmod(c.NginxCommitSocket, 0600); err != nil {
		return err
	}
	go func() { <-ctx.Done(); _ = ln.Close() }()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			continue
		}
		go func() {
			defer conn.Close()
			var req NginxCommitRequest
			if json.NewDecoder(io.LimitReader(conn, 2<<20)).Decode(&req) != nil {
				return
			}
			callCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
			defer cancel()
			err := commitNginxVhost(callCtx, req)
			res := NginxCommitResponse{OK: err == nil}
			if err != nil {
				res.Error = redact(err.Error())
			}
			_ = json.NewEncoder(conn).Encode(res)
		}()
	}
}

func CallNginxCommit(ctx context.Context, c Config, domain, content string) error {
	return callNginxCommit(ctx, c, NginxCommitRequest{Version: ProtocolVersion, Domain: domain, Content: content})
}

// CallNginxCommitWithPageSpeedPrerequisite is deliberately not a general
// global-Nginx write API. The commit service independently derives and checks
// the one allowed FileCachePath change from the active nginx.conf.
func CallNginxCommitWithPageSpeedPrerequisite(ctx context.Context, c Config, domain, content, globalContent string) error {
	return callNginxCommit(ctx, c, NginxCommitRequest{
		Version: ProtocolVersion, Domain: domain, Content: content,
		GlobalContent: globalContent, EnsurePageSpeedCachePath: true,
	})
}

func callNginxCommit(ctx context.Context, c Config, req NginxCommitRequest) error {
	if err := ValidateDomain(req.Domain); err != nil {
		return err
	}
	if len(req.Content) == 0 || len(req.Content) > 900<<10 || len(req.GlobalContent) > 900<<10 {
		return errors.New("invalid generated vhost content")
	}
	d := net.Dialer{Timeout: 5 * time.Second}
	conn, err := d.DialContext(ctx, "unix", c.NginxCommitSocket)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err = json.NewEncoder(conn).Encode(req); err != nil {
		return err
	}
	var res NginxCommitResponse
	if err = json.NewDecoder(io.LimitReader(conn, 1<<20)).Decode(&res); err != nil {
		return err
	}
	if !res.OK {
		return errors.New(res.Error)
	}
	return nil
}

func commitNginxVhost(ctx context.Context, req NginxCommitRequest) error {
	if req.Version != ProtocolVersion {
		return errors.New("unsupported nginx commit protocol")
	}
	if err := ValidateDomain(req.Domain); err != nil {
		return err
	}
	if len(req.Content) == 0 || len(req.Content) > 900<<10 || len(req.GlobalContent) > 900<<10 {
		return errors.New("invalid generated vhost content")
	}
	path := filepath.Join("/etc/nginx/sites-enabled", req.Domain+".conf")
	before, err := os.ReadFile(path)
	if err != nil {
		return errors.New("CloudPanel vhost not found")
	}
	var globalPath string
	var globalBefore []byte
	if req.GlobalContent != "" {
		globalPath = "/etc/nginx/nginx.conf"
		globalBefore, err = os.ReadFile(globalPath)
		if err != nil {
			return err
		}
		expected, err := pageSpeedGlobalConfig(string(globalBefore))
		if err != nil || req.GlobalContent != expected {
			return errors.New("invalid pagespeed global configuration request")
		}
	}
	if req.EnsurePageSpeedCachePath {
		if err := ensurePageSpeedCachePath(); err != nil {
			return err
		}
	}
	if globalPath != "" {
		if err := writeNginxFile(globalPath, req.GlobalContent, 0644); err != nil {
			return err
		}
	}
	if err := writeNginxFile(path, req.Content, 0640); err != nil {
		if globalPath != "" {
			_ = writeNginxFile(globalPath, string(globalBefore), 0644)
		}
		return err
	}
	rollback := func() {
		_ = writeNginxFile(path, string(before), 0640)
		if globalPath != "" {
			_ = writeNginxFile(globalPath, string(globalBefore), 0644)
		}
		_ = exec.CommandContext(context.Background(), "systemctl", "reload", "nginx").Run()
	}
	if out, e := exec.CommandContext(ctx, "nginx", "-t").CombinedOutput(); e != nil {
		rollback()
		return fmt.Errorf("nginx validation failed: %s", redact(string(out)))
	}
	if out, e := exec.CommandContext(ctx, "systemctl", "reload", "nginx").CombinedOutput(); e != nil {
		rollback()
		return fmt.Errorf("nginx reload failed: %s", redact(string(out)))
	}
	return nil
}

func writeNginxFile(path, content string, mode os.FileMode) error {
	// ProtectSystem allows this service to write nginx.conf itself, but not to
	// create a sibling temporary file without granting write access to all of
	// /etc/nginx. Keep that boundary: this path is accepted only for the fixed,
	// independently verified PageSpeed FileCachePath patch above. Validation and
	// rollback happen before this request returns.
	if path == "/etc/nginx/nginx.conf" {
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, mode)
		if err != nil {
			return err
		}
		if _, err = f.WriteString(content); err == nil {
			err = f.Sync()
		}
		if closeErr := f.Close(); err == nil {
			err = closeErr
		}
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".gateway-")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err = tmp.Chmod(mode); err == nil {
		_, err = tmp.WriteString(content)
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}
