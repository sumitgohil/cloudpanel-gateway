package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// Version is replaced by the release workflow with -ldflags. Source builds
// intentionally report dev rather than claiming to be a released version.
var Version = "dev"

func NewRootCommand() *cobra.Command {
	var configPath string
	root := &cobra.Command{Use: "cloudpanel-gateway", Short: "Secure API, MCP gateway, and local CLI for CloudPanel", Long: "CloudPanel Gateway exposes an authenticated REST API and MCP endpoint while executing only typed allowlisted CloudPanel CLI actions.", SilenceUsage: true}
	root.PersistentFlags().StringVar(&configPath, "config", "/etc/cloudpanel-gateway/config.json", "configuration file")
	load := func(create bool) (Config, *State, error) {
		c, e := LoadConfig(configPath)
		if e != nil {
			return c, nil, e
		}
		s, e := OpenState(c, create)
		return c, s, e
	}
	root.AddCommand(&cobra.Command{Use: "serve", Short: "Run the unprivileged HTTP API and MCP gateway", RunE: func(cmd *cobra.Command, args []string) error {
		c, s, e := load(false)
		if e != nil {
			return e
		}
		defer s.Close()
		logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
		server := NewAPIServer(c, s, logger)
		logger.Info("gateway starting", "listen", c.Listen)
		return (&httpServer{addr: c.Listen, handler: server.Handler()}).run(cmd.Context())
	}})
	root.AddCommand(&cobra.Command{Use: "helper", Short: "Run the root-only CloudPanel CLI helper", RunE: func(cmd *cobra.Command, args []string) error {
		if e := requireRoot(); e != nil {
			return e
		}
		c, s, e := load(false)
		if e != nil {
			return e
		}
		defer s.Close()
		return ListenHelper(cmd.Context(), c, s)
	}})
	root.AddCommand(&cobra.Command{Use: "nginx-commit", Short: "Run the isolated root-only Nginx validation and commit service", RunE: func(cmd *cobra.Command, args []string) error {
		if e := requireRoot(); e != nil {
			return e
		}
		c, s, e := load(false)
		if e != nil {
			return e
		}
		defer s.Close()
		return ListenNginxCommit(cmd.Context(), c)
	}})
	root.AddCommand(bootstrapCmd(load), tokenCmd(load), policyCmd(load), domainCmd(load), settingsCmd(load), tlsCmd(load), fileCmd(load), backupCmd(load), nodeCmd(load), doctorCmd(load), serviceCmd(load), completionCmd(root))
	root.AddCommand(&cobra.Command{Use: "version", Short: "Print version", Run: func(cmd *cobra.Command, args []string) { fmt.Fprintln(cmd.OutOrStdout(), Version) }})
	return root
}

type stateLoader func(bool) (Config, *State, error)

func requireRoot() error {
	if os.Geteuid() != 0 {
		return errors.New("this command must be run as root")
	}
	return nil
}
func bootstrapCmd(load stateLoader) *cobra.Command {
	var output string
	cmd := &cobra.Command{Use: "bootstrap", Short: "Initialize state and create the first administrator token", RunE: func(cmd *cobra.Command, args []string) error {
		if e := requireRoot(); e != nil {
			return e
		}
		c, s, e := load(true)
		if e != nil {
			return e
		}
		defer s.Close()
		if output == "" {
			output = "/root/cloudpanel-gateway-bootstrap-token.txt"
		}
		if _, e := os.Stat(output); e == nil {
			return fmt.Errorf("refusing to overwrite existing bootstrap token file %s", output)
		}
		_, raw, e := s.CreateToken("bootstrap-admin", []string{"admin", "docs:read", "metrics:read", "artifacts:write"}, nil)
		if e != nil {
			return e
		}
		if e := os.MkdirAll(filepath.Dir(output), 0700); e != nil {
			return e
		}
		if e := os.WriteFile(output, []byte(raw+"\n"), 0600); e != nil {
			return e
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Bootstrap token written once to %s. Store it securely and delete the file.\n", output)
		fmt.Fprintf(cmd.OutOrStdout(), "Gateway database: %s\n", c.Database)
		return nil
	}}
	cmd.Flags().StringVar(&output, "bootstrap-token-file", "/root/cloudpanel-gateway-bootstrap-token.txt", "root-only file for the one-time token")
	return cmd
}
func tokenCmd(load stateLoader) *cobra.Command {
	cmd := &cobra.Command{Use: "token", Short: "Manage API and MCP bearer tokens"}
	var label, scopes, expires string
	create := &cobra.Command{Use: "create", Short: "Create a token; the plaintext token is printed once", RunE: func(cmd *cobra.Command, args []string) error {
		if e := requireRoot(); e != nil {
			return e
		}
		_, s, e := load(false)
		if e != nil {
			return e
		}
		defer s.Close()
		ss, e := ParseScopes(scopes)
		if e != nil {
			return e
		}
		var exp *time.Time
		if expires != "" {
			v, e := time.Parse(time.RFC3339, expires)
			if e != nil {
				return e
			}
			exp = &v
		}
		t, raw, e := s.CreateToken(label, ss, exp)
		if e != nil {
			return e
		}
		fmt.Fprintf(cmd.OutOrStdout(), "id: %s\ntoken: %s\n", t.ID, raw)
		return nil
	}}
	create.Flags().StringVar(&label, "label", "", "human-readable token label")
	create.Flags().StringVar(&scopes, "scopes", "", "comma-separated scopes")
	create.Flags().StringVar(&expires, "expires-at", "", "optional RFC3339 expiry")
	create.MarkFlagRequired("label")
	create.MarkFlagRequired("scopes")
	list := &cobra.Command{Use: "list", Short: "List tokens without plaintext values", RunE: func(cmd *cobra.Command, args []string) error {
		if e := requireRoot(); e != nil {
			return e
		}
		_, s, e := load(false)
		if e != nil {
			return e
		}
		defer s.Close()
		v, e := s.ListTokens()
		if e != nil {
			return e
		}
		return json.NewEncoder(cmd.OutOrStdout()).Encode(v)
	}}
	var id string
	revoke := &cobra.Command{Use: "revoke", Short: "Revoke a token", RunE: func(cmd *cobra.Command, args []string) error {
		if e := requireRoot(); e != nil {
			return e
		}
		_, s, e := load(false)
		if e != nil {
			return e
		}
		defer s.Close()
		return s.RevokeToken(id)
	}}
	revoke.Flags().StringVar(&id, "id", "", "token ID")
	revoke.MarkFlagRequired("id")
	var rotateID, rotateLabel, rotateScopes string
	rotate := &cobra.Command{Use: "rotate", Short: "Create a replacement token and revoke the old one", RunE: func(cmd *cobra.Command, args []string) error {
		if e := requireRoot(); e != nil {
			return e
		}
		_, s, e := load(false)
		if e != nil {
			return e
		}
		defer s.Close()
		ss, e := ParseScopes(rotateScopes)
		if e != nil {
			return e
		}
		t, raw, e := s.CreateToken(rotateLabel, ss, nil)
		if e != nil {
			return e
		}
		if e := s.RevokeToken(rotateID); e != nil {
			return e
		}
		fmt.Fprintf(cmd.OutOrStdout(), "id: %s\ntoken: %s\n", t.ID, raw)
		return nil
	}}
	rotate.Flags().StringVar(&rotateID, "id", "", "active token ID to revoke")
	rotate.Flags().StringVar(&rotateLabel, "label", "", "replacement token label")
	rotate.Flags().StringVar(&rotateScopes, "scopes", "", "replacement comma-separated scopes")
	rotate.MarkFlagRequired("id")
	rotate.MarkFlagRequired("label")
	rotate.MarkFlagRequired("scopes")
	cmd.AddCommand(create, list, revoke, rotate)
	return cmd
}
func policyCmd(load stateLoader) *cobra.Command {
	cmd := &cobra.Command{Use: "policy", Short: "Enable or disable high-risk operations"}
	var op string
	set := func(enabled bool) *cobra.Command {
		return &cobra.Command{Use: map[bool]string{true: "enable", false: "disable"}[enabled], Short: "Change a dangerous-operation policy", RunE: func(cmd *cobra.Command, args []string) error {
			if e := requireRoot(); e != nil {
				return e
			}
			spec, ok := Actions[op]
			managed := op == "file.deploy_artifact" || op == "file.deploy_root" || op == "backup.restore" || op == "node.server_build" || op == "node.deploy_release" || op == "node.runtime_manage"
			if !ok && !managed {
				return errors.New("unknown operation")
			}
			if ok && !spec.Dangerous && !managed {
				return errors.New("only dangerous operations are policy controlled")
			}
			_, s, e := load(false)
			if e != nil {
				return e
			}
			defer s.Close()
			return s.SetPolicy(op, enabled)
		}}
	}
	enable := set(true)
	disable := set(false)
	enable.Flags().StringVar(&op, "operation", "", "operation name")
	disable.Flags().StringVar(&op, "operation", "", "operation name")
	enable.MarkFlagRequired("operation")
	disable.MarkFlagRequired("operation")
	list := &cobra.Command{Use: "list", Short: "List dangerous operations and their status", RunE: func(cmd *cobra.Command, args []string) error {
		_, s, e := load(false)
		if e != nil {
			return e
		}
		defer s.Close()
		out := map[string]bool{}
		for n, spec := range Actions {
			if spec.Dangerous {
				v, _ := s.Allowed(n)
				out[n] = v
			}
		}
		for _, n := range []string{"file.deploy_artifact", "file.deploy_root", "backup.restore", "node.server_build", "node.deploy_release", "node.runtime_manage"} {
			v, _ := s.Allowed(n)
			out[n] = v
		}
		return json.NewEncoder(cmd.OutOrStdout()).Encode(out)
	}}
	cmd.AddCommand(enable, disable, list)
	return cmd
}
func domainCmd(load stateLoader) *cobra.Command {
	cmd := &cobra.Command{Use: "domain", Short: "Map a public domain to the gateway through CloudPanel"}
	var domain, target, expected string
	mapCmd := &cobra.Command{Use: "map", Short: "Create a CloudPanel reverse proxy for a domain", Example: "cloudpanel-gateway domain map --domain panel1.psng.tech", RunE: func(cmd *cobra.Command, args []string) error {
		if e := requireRoot(); e != nil {
			return e
		}
		if e := ValidateDomain(domain); e != nil {
			return e
		}
		ips, e := net.LookupIP(domain)
		if e != nil || len(ips) == 0 {
			return fmt.Errorf("DNS for %s does not resolve", domain)
		}
		if expected != "" {
			found := false
			for _, ip := range ips {
				if ip.String() == expected {
					found = true
				}
			}
			if !found {
				return fmt.Errorf("DNS for %s does not contain %s", domain, expected)
			}
		}
		c, s, e := load(false)
		if e != nil {
			return e
		}
		defer s.Close()
		if _, _, e := s.Domain(domain); e == nil {
			return errors.New("domain is already mapped")
		}
		user := "cpgw" + strings.ReplaceAll(strings.ReplaceAll(domain, ".", ""), "-", "")
		if len(user) > 20 {
			user = user[:20]
		}
		password, e := newID("", 24)
		if e != nil {
			return e
		}
		if target == "" {
			target = "http://" + c.Listen
		}
		res, e := CallHelper(cmd.Context(), c, "site.create_reverse_proxy", map[string]string{"domainName": domain, "reverseProxyUrl": target, "siteUser": user, "siteUserPassword": password})
		if e != nil {
			return e
		}
		if !res.OK {
			return errors.New(res.Error)
		}
		if e := s.StoreDomain(domain, user, password); e != nil {
			return e
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Mapped %s to %s. Issue TLS separately with: cloudpanel-gateway domain tls issue --domain %s\n", domain, target, domain)
		return nil
	}}
	mapCmd.Flags().StringVar(&domain, "domain", "", "public FQDN")
	mapCmd.Flags().StringVar(&target, "target-url", "", "loopback gateway URL (default configured listener)")
	mapCmd.Flags().StringVar(&expected, "expected-ip", "", "optional public IP that DNS must contain")
	mapCmd.MarkFlagRequired("domain")
	var adoptDomain string
	adopt := &cobra.Command{Use: "adopt", Short: "Record an already-created CloudPanel gateway proxy", RunE: func(cmd *cobra.Command, args []string) error {
		if e := requireRoot(); e != nil {
			return e
		}
		if e := ValidateDomain(adoptDomain); e != nil {
			return e
		}
		_, s, e := load(false)
		if e != nil {
			return e
		}
		defer s.Close()
		user := "cpgw" + strings.ReplaceAll(strings.ReplaceAll(adoptDomain, ".", ""), "-", "")
		if len(user) > 20 {
			user = user[:20]
		}
		if e := s.StoreDomain(adoptDomain, user, ""); e != nil {
			return e
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Adopted %s into gateway state.\n", adoptDomain)
		return nil
	}}
	adopt.Flags().StringVar(&adoptDomain, "domain", "", "mapped FQDN")
	adopt.MarkFlagRequired("domain")
	var statusDomain string
	status := &cobra.Command{Use: "status", Short: "Show a locally recorded gateway domain mapping", RunE: func(cmd *cobra.Command, args []string) error {
		_, s, e := load(false)
		if e != nil {
			return e
		}
		defer s.Close()
		user, _, e := s.Domain(statusDomain)
		if e != nil {
			return errors.New("domain is not mapped")
		}
		return json.NewEncoder(cmd.OutOrStdout()).Encode(map[string]string{"domain": statusDomain, "site_user": user})
	}}
	status.Flags().StringVar(&statusDomain, "domain", "", "mapped FQDN")
	status.MarkFlagRequired("domain")
	var unmapDomain string
	unmap := &cobra.Command{Use: "unmap", Short: "Delete the CloudPanel reverse proxy and local mapping", RunE: func(cmd *cobra.Command, args []string) error {
		if e := requireRoot(); e != nil {
			return e
		}
		c, s, e := load(false)
		if e != nil {
			return e
		}
		defer s.Close()
		if _, _, e := s.Domain(unmapDomain); e != nil {
			return errors.New("domain is not mapped")
		}
		res, e := CallHelper(cmd.Context(), c, "site.delete", map[string]string{"domainName": unmapDomain})
		if e != nil {
			return e
		}
		if !res.OK {
			return errors.New(res.Error)
		}
		return s.DeleteDomain(unmapDomain)
	}}
	unmap.Flags().StringVar(&unmapDomain, "domain", "", "mapped FQDN")
	unmap.MarkFlagRequired("domain")
	var tlsDomain string
	tls := &cobra.Command{Use: "tls", Short: "Manage TLS for mapped domains"}
	issue := &cobra.Command{Use: "issue", Short: "Request a Let's Encrypt certificate", RunE: func(cmd *cobra.Command, args []string) error {
		if e := requireRoot(); e != nil {
			return e
		}
		c, s, e := load(false)
		if e != nil {
			return e
		}
		defer s.Close()
		if _, _, e := s.Domain(tlsDomain); e != nil {
			return errors.New("domain is not mapped")
		}
		res, e := CallHelper(cmd.Context(), c, "certificate.lets_encrypt", map[string]string{"domainName": tlsDomain})
		if e != nil {
			return e
		}
		if !res.OK {
			return errors.New(res.Error)
		}
		fmt.Fprintln(cmd.OutOrStdout(), "certificate issued")
		return nil
	}}
	issue.Flags().StringVar(&tlsDomain, "domain", "", "mapped FQDN")
	issue.MarkFlagRequired("domain")
	tls.AddCommand(issue)
	cmd.AddCommand(mapCmd, adopt, status, unmap, tls)
	return cmd
}

func settingsCmd(load stateLoader) *cobra.Command {
	call := func(cmd *cobra.Command, request SettingsRequest) error {
		if err := requireRoot(); err != nil {
			return err
		}
		c, s, err := load(false)
		if err != nil {
			return err
		}
		defer s.Close()
		var out any
		if err = CallSettingsHelper(cmd.Context(), c, request, &out); err != nil {
			return err
		}
		return json.NewEncoder(cmd.OutOrStdout()).Encode(out)
	}
	site := &cobra.Command{Use: "site", Short: "Inspect and safely update CloudPanel site settings"}
	var domain string
	get := &cobra.Command{Use: "settings", Short: "Get site settings", RunE: func(cmd *cobra.Command, args []string) error {
		return call(cmd, SettingsRequest{Operation: settingsGet, Domain: domain})
	}}
	get.Flags().StringVar(&domain, "domain", "", "site domain")
	_ = get.MarkFlagRequired("domain")
	var root, revision string
	var confirm bool
	rootCmd := &cobra.Command{Use: "root", Short: "Update a site's htdocs-relative root directory", RunE: func(cmd *cobra.Command, args []string) error {
		return call(cmd, SettingsRequest{Operation: settingsUpdateRoot, Domain: domain, RootDirectory: root, IfMatchRevision: revision, Confirm: confirm})
	}}
	rootCmd.Flags().StringVar(&domain, "domain", "", "site domain")
	rootCmd.Flags().StringVar(&root, "root-directory", "", "existing directory relative to htdocs")
	rootCmd.Flags().StringVar(&revision, "if-match-revision", "", "revision from site settings")
	rootCmd.Flags().BoolVar(&confirm, "confirm", false, "confirm this root-directory change")
	_ = rootCmd.MarkFlagRequired("domain")
	_ = rootCmd.MarkFlagRequired("root-directory")
	_ = rootCmd.MarkFlagRequired("if-match-revision")
	var passDomain, passRevision string
	var passConfirm bool
	password := &cobra.Command{Use: "user rotate-password", Short: "Generate and rotate the site user's SSH/SFTP password", RunE: func(cmd *cobra.Command, args []string) error {
		return call(cmd, SettingsRequest{Operation: settingsRotatePass, Domain: passDomain, IfMatchRevision: passRevision, Confirm: passConfirm})
	}}
	password.Flags().StringVar(&passDomain, "domain", "", "site domain")
	password.Flags().StringVar(&passRevision, "if-match-revision", "", "revision from site settings")
	password.Flags().BoolVar(&passConfirm, "confirm", false, "confirm password rotation")
	_ = password.MarkFlagRequired("domain")
	_ = password.MarkFlagRequired("if-match-revision")
	site.AddCommand(get, rootCmd, password)
	php := &cobra.Command{Use: "php", Short: "Inspect and update reviewed PHP settings"}
	var phpDomain, phpRevision string
	var values []string
	phpGet := &cobra.Command{Use: "get", Short: "Get PHP settings", RunE: func(cmd *cobra.Command, args []string) error {
		return call(cmd, SettingsRequest{Operation: settingsGetPHP, Domain: phpDomain})
	}}
	phpGet.Flags().StringVar(&phpDomain, "domain", "", "site domain")
	_ = phpGet.MarkFlagRequired("domain")
	phpUpdate := &cobra.Command{Use: "update", Short: "Update safe PHP settings", RunE: func(cmd *cobra.Command, args []string) error {
		v, err := parseSetValues(values)
		if err != nil {
			return err
		}
		return call(cmd, SettingsRequest{Operation: settingsUpdatePHP, Domain: phpDomain, IfMatchRevision: phpRevision, PHPValues: v})
	}}
	phpUpdate.Flags().StringVar(&phpDomain, "domain", "", "site domain")
	phpUpdate.Flags().StringVar(&phpRevision, "if-match-revision", "", "revision from php get")
	phpUpdate.Flags().StringSliceVar(&values, "set", nil, "key=value (repeatable)")
	_ = phpUpdate.MarkFlagRequired("domain")
	_ = phpUpdate.MarkFlagRequired("if-match-revision")
	php.AddCommand(phpGet, phpUpdate)
	pagespeed := &cobra.Command{Use: "pagespeed", Short: "Inspect, configure, and purge PageSpeed"}
	var psDomain, psRevision, psPreset string
	var psEnabled bool
	var enable, disable []string
	psGet := &cobra.Command{Use: "get", Short: "Get PageSpeed settings", RunE: func(cmd *cobra.Command, args []string) error {
		return call(cmd, SettingsRequest{Operation: settingsGetPageSpeed, Domain: psDomain})
	}}
	psGet.Flags().StringVar(&psDomain, "domain", "", "site domain")
	_ = psGet.MarkFlagRequired("domain")
	psUpdate := &cobra.Command{Use: "update", Short: "Update PageSpeed preset and filters", RunE: func(cmd *cobra.Command, args []string) error {
		return call(cmd, SettingsRequest{Operation: settingsUpdatePS, Domain: psDomain, IfMatchRevision: psRevision, PageSpeed: &PageSpeedUpdate{Enabled: psEnabled, Preset: psPreset, EnableFilters: enable, DisableFilters: disable}})
	}}
	psUpdate.Flags().StringVar(&psDomain, "domain", "", "site domain")
	psUpdate.Flags().StringVar(&psRevision, "if-match-revision", "", "revision from pagespeed get")
	psUpdate.Flags().BoolVar(&psEnabled, "enabled", false, "enable PageSpeed")
	psUpdate.Flags().StringVar(&psPreset, "preset", "core", "core, image, or cloudpanel-default")
	psUpdate.Flags().StringSliceVar(&enable, "enable-filter", nil, "allowlisted filter to enable")
	psUpdate.Flags().StringSliceVar(&disable, "disable-filter", nil, "allowlisted filter to disable")
	_ = psUpdate.MarkFlagRequired("domain")
	_ = psUpdate.MarkFlagRequired("if-match-revision")
	psPurge := &cobra.Command{Use: "purge", Short: "Purge only this site's PageSpeed cache", RunE: func(cmd *cobra.Command, args []string) error {
		return call(cmd, SettingsRequest{Operation: settingsPurgePS, Domain: psDomain})
	}}
	psPurge.Flags().StringVar(&psDomain, "domain", "", "site domain")
	_ = psPurge.MarkFlagRequired("domain")
	pagespeed.AddCommand(psGet, psUpdate, psPurge)
	cmd := &cobra.Command{Use: "settings", Short: "CloudPanel site, PHP, and PageSpeed controls", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, args []string) error { return cmd.Help() }}
	cmd.AddCommand(site, php, pagespeed)
	return cmd
}

func typedLocalCall(load stateLoader, cmd *cobra.Command, request HelperRequest) error {
	if err := requireRoot(); err != nil {
		return err
	}
	c, s, err := load(false)
	if err != nil {
		return err
	}
	defer s.Close()
	var out any
	if err = CallTypedHelper(cmd.Context(), c, request, &out); err != nil {
		return err
	}
	return json.NewEncoder(cmd.OutOrStdout()).Encode(out)
}

func tlsCmd(load stateLoader) *cobra.Command {
	cmd := &cobra.Command{Use: "tls", Short: "Read active TLS certificate status without exposing key material"}
	var domain string
	status := &cobra.Command{Use: "status", Short: "Show issuer, expiry, SANs, consistency, and expiry-based renewal health", RunE: func(c *cobra.Command, args []string) error {
		return typedLocalCall(load, c, HelperRequest{TLS: &TLSRequest{Domain: domain}})
	}}
	status.Flags().StringVar(&domain, "domain", "", "site domain")
	_ = status.MarkFlagRequired("domain")
	cmd.AddCommand(status)
	return cmd
}

func fileCmd(load stateLoader) *cobra.Command {
	cmd := &cobra.Command{Use: "file", Short: "Safely deploy managed artifacts"}
	var domain, artifact, target string
	var replace, confirm bool
	deploy := &cobra.Command{Use: "deploy-artifact", Short: "Deploy a managed ZIP artifact to a site-root-relative directory", Example: "cloudpanel-gateway file deploy-artifact --domain example.com --artifact-id artifact_x --target-dir releases/current", RunE: func(c *cobra.Command, args []string) error {
		return typedLocalCall(load, c, HelperRequest{Deploy: &DeployRequest{Domain: domain, ArtifactID: artifact, TargetDir: target, Replace: replace, Confirm: confirm}})
	}}
	deploy.Flags().StringVar(&domain, "domain", "", "site domain")
	deploy.Flags().StringVar(&artifact, "artifact-id", "", "managed artifact ID")
	deploy.Flags().StringVar(&target, "target-dir", "", "site-root-relative target directory")
	deploy.Flags().BoolVar(&replace, "replace", false, "replace a non-empty target only with --confirm")
	deploy.Flags().BoolVar(&confirm, "confirm", false, "confirm replacement")
	_ = deploy.MarkFlagRequired("domain")
	_ = deploy.MarkFlagRequired("artifact-id")
	_ = deploy.MarkFlagRequired("target-dir")
	var rootDomain, rootArtifact string
	var rootReplace, rootConfirm bool
	rootDeploy := &cobra.Command{Use: "deploy-root-artifact", Short: "Replace a site's active root after creating a mandatory safety backup", Example: "cloudpanel-gateway file deploy-root-artifact --domain example.com --artifact-id artifact_x --replace --confirm", RunE: func(c *cobra.Command, args []string) error {
		return typedLocalCall(load, c, HelperRequest{Deploy: &DeployRequest{Domain: rootDomain, ArtifactID: rootArtifact, Replace: rootReplace, Confirm: rootConfirm, Root: true}})
	}}
	rootDeploy.Flags().StringVar(&rootDomain, "domain", "", "site domain")
	rootDeploy.Flags().StringVar(&rootArtifact, "artifact-id", "", "managed artifact ID")
	rootDeploy.Flags().BoolVar(&rootReplace, "replace", false, "required acknowledgement that the active root will be replaced")
	rootDeploy.Flags().BoolVar(&rootConfirm, "confirm", false, "confirm root replacement")
	_ = rootDeploy.MarkFlagRequired("domain")
	_ = rootDeploy.MarkFlagRequired("artifact-id")
	cmd.AddCommand(deploy, rootDeploy)
	return cmd
}

func backupCmd(load stateLoader) *cobra.Command {
	cmd := &cobra.Command{Use: "backup", Short: "Create, list, and restore encrypted managed site backups"}
	var domain, components string
	create := &cobra.Command{Use: "create", Short: "Create an encrypted local backup", RunE: func(c *cobra.Command, args []string) error {
		return typedLocalCall(load, c, HelperRequest{Backup: &BackupRequest{Operation: "create", Domain: domain, Components: components}})
	}}
	create.Flags().StringVar(&domain, "domain", "", "site domain")
	create.Flags().StringVar(&components, "components", "", "files, databases, or both")
	_ = create.MarkFlagRequired("domain")
	_ = create.MarkFlagRequired("components")
	var listDomain string
	list := &cobra.Command{Use: "list", Short: "List managed encrypted backups and retention", RunE: func(c *cobra.Command, args []string) error {
		return typedLocalCall(load, c, HelperRequest{Backup: &BackupRequest{Operation: "list", Domain: listDomain}})
	}}
	list.Flags().StringVar(&listDomain, "domain", "", "site domain")
	_ = list.MarkFlagRequired("domain")
	var restoreDomain, backupID, restoreComponents string
	var confirm bool
	restore := &cobra.Command{Use: "restore", Short: "Restore selected components after a mandatory safety backup", RunE: func(c *cobra.Command, args []string) error {
		return typedLocalCall(load, c, HelperRequest{Backup: &BackupRequest{Operation: "restore", Domain: restoreDomain, BackupID: backupID, Components: restoreComponents, Confirm: confirm}})
	}}
	restore.Flags().StringVar(&restoreDomain, "domain", "", "site domain")
	restore.Flags().StringVar(&backupID, "backup-id", "", "managed backup ID")
	restore.Flags().StringVar(&restoreComponents, "components", "", "files, databases, or both")
	restore.Flags().BoolVar(&confirm, "confirm", false, "confirm restore")
	_ = restore.MarkFlagRequired("domain")
	_ = restore.MarkFlagRequired("backup-id")
	_ = restore.MarkFlagRequired("components")
	cmd.AddCommand(create, list, restore)
	return cmd
}

func nodeCmd(load stateLoader) *cobra.Command {
	cmd := &cobra.Command{Use: "node", Short: "Manage CloudPanel Node.js releases and generated systemd services"}
	var domain, artifact, framework, entrypoint, version, health, revision string
	var args []string
	var port int
	var confirm bool
	call := func(operation string, c *cobra.Command) error {
		return typedLocalCall(load, c, HelperRequest{Node: &NodeRequest{Operation: operation, Domain: domain, ArtifactID: artifact, Framework: framework, Entrypoint: entrypoint, Args: args, NodeVersion: version, AppPort: port, HealthPath: health, IfMatchRevision: revision, Confirm: confirm}})
	}
	get := &cobra.Command{Use: "settings", Short: "Show CloudPanel Node.js version, app port, and gateway revision", RunE: func(c *cobra.Command, _ []string) error { return call(nodeGetSettings, c) }}
	status := &cobra.Command{Use: "status", Short: "Show generated service and loopback readiness", RunE: func(c *cobra.Command, _ []string) error { return call(nodeStatus, c) }}
	update := &cobra.Command{Use: "update-settings", Short: "Update the managed runtime settings after an explicit confirmation", RunE: func(c *cobra.Command, _ []string) error { return call(nodeUpdate, c) }}
	deploy := &cobra.Command{Use: "deploy-release", Short: "Deploy a managed Node.js ZIP artifact as an atomic release", RunE: func(c *cobra.Command, _ []string) error { return call(nodeDeploy, c) }}
	restart := &cobra.Command{Use: "restart", Short: "Restart the generated Node.js service", RunE: func(c *cobra.Command, _ []string) error { return call(nodeRestart, c) }}
	list := &cobra.Command{Use: "releases", Short: "List retained Node.js releases", RunE: func(c *cobra.Command, _ []string) error { return call(nodeList, c) }}
	rollback := &cobra.Command{Use: "rollback", Short: "Activate the previous Node.js release", RunE: func(c *cobra.Command, _ []string) error { return call(nodeRollback, c) }}
	for _, c := range []*cobra.Command{get, status, update, deploy, restart, list, rollback} {
		c.Flags().StringVar(&domain, "domain", "", "CloudPanel Node.js domain")
		_ = c.MarkFlagRequired("domain")
	}
	update.Flags().StringVar(&version, "node-version", "", "CloudPanel Node.js version")
	update.Flags().IntVar(&port, "app-port", 0, "loopback application port")
	update.Flags().StringVar(&health, "health-path", "", "optional HTTP health path")
	update.Flags().StringVar(&revision, "if-match-revision", "", "current Node.js settings revision")
	update.Flags().BoolVar(&confirm, "confirm", false, "confirm runtime change")
	deploy.Flags().StringVar(&artifact, "artifact-id", "", "managed artifact ID")
	deploy.Flags().StringVar(&framework, "framework", "generic-node", "generic-node, astro, next-standalone, or nuxt-node")
	deploy.Flags().StringVar(&entrypoint, "entrypoint", "", "relative .js/.mjs/.cjs entrypoint")
	deploy.Flags().StringSliceVar(&args, "arg", nil, "safe Node.js argument; repeat as needed")
	deploy.Flags().StringVar(&health, "health-path", "", "optional HTTP health path")
	_ = deploy.MarkFlagRequired("artifact-id")
	_ = deploy.MarkFlagRequired("entrypoint")
	restart.Flags().BoolVar(&confirm, "confirm", false, "confirm restart")
	rollback.Flags().BoolVar(&confirm, "confirm", false, "confirm rollback")
	cmd.AddCommand(get, status, update, deploy, restart, list, rollback)
	return cmd
}

func parseSetValues(items []string) (map[string]string, error) {
	out := map[string]string{}
	for _, item := range items {
		parts := strings.SplitN(item, "=", 2)
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			return nil, fmt.Errorf("invalid --set %q; use key=value", item)
		}
		out[parts[0]] = parts[1]
	}
	if len(out) == 0 {
		return nil, errors.New("at least one --set key=value is required")
	}
	return out, nil
}
func doctorCmd(load stateLoader) *cobra.Command {
	return &cobra.Command{Use: "doctor", Short: "Check CloudPanel Gateway prerequisites", RunE: func(cmd *cobra.Command, args []string) error {
		c, s, e := load(false)
		if e != nil {
			return e
		}
		defer s.Close()
		result := map[string]any{"database": true, "config": c, "clpctl": false, "helper": false}
		if out, e := exec.Command("clpctl", "--version").Output(); e == nil {
			result["clpctl"] = strings.TrimSpace(string(out))
		}
		if _, e := CallHelper(cmd.Context(), c, "user.list", nil); e == nil {
			result["helper"] = true
		}
		return json.NewEncoder(cmd.OutOrStdout()).Encode(result)
	}}
}
func serviceCmd(load stateLoader) *cobra.Command {
	return &cobra.Command{Use: "service", Short: "Inspect local service state", RunE: func(cmd *cobra.Command, args []string) error {
		c, _, e := load(false)
		if e != nil {
			return e
		}
		return json.NewEncoder(cmd.OutOrStdout()).Encode(map[string]string{"listen": c.Listen, "helper_socket": c.HelperSocket})
	}}
}
func completionCmd(root *cobra.Command) *cobra.Command {
	return &cobra.Command{Use: "completion [bash|zsh|fish]", Short: "Generate shell completion", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		switch args[0] {
		case "bash":
			return root.GenBashCompletion(cmd.OutOrStdout())
		case "zsh":
			return root.GenZshCompletion(cmd.OutOrStdout())
		case "fish":
			return root.GenFishCompletion(cmd.OutOrStdout(), true)
		}
		return errors.New("supported shells: bash, zsh, fish")
	}}
}

// httpServer keeps the command layer free of net/http details and provides graceful shutdown.
type httpServer struct {
	addr    string
	handler interface {
		ServeHTTP(http.ResponseWriter, *http.Request)
	}
}

func (s *httpServer) run(ctx context.Context) error {
	// Deployments are bounded to 100 MiB and backups have a helper-enforced
	// 15-minute ceiling. These timeouts keep those legitimate operations from
	// being cut off while the request body and helper protocols stay bounded.
	srv := &http.Server{Addr: s.addr, Handler: s.handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 5 * time.Minute, WriteTimeout: 16 * time.Minute, IdleTimeout: 60 * time.Second}
	done := make(chan error, 1)
	go func() { done <- srv.ListenAndServe() }()
	select {
	case e := <-done:
		if errors.Is(e, http.ErrServerClosed) {
			return nil
		}
		return e
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return srv.Shutdown(shutdown)
	}
}
