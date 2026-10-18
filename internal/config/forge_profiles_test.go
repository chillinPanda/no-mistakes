package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadGlobalGitHubWebHost(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, host, provider, want string
	}{
		{"omitted", "", "gh_config_dir", ""},
		{"public GitHub", "github.com", "gh_config_dir", "github.com"},
		{"enterprise", "git.corp.example", "gh_config_dir", "git.corp.example"},
		{"normalized", " GitHub.COM ", "gh_config_dir", "github.com"},
		{"URL", "https://github.com", "gh_config_dir", "error"},
		{"path", "github.com/acme", "gh_config_dir", "error"},
		{"port", "github.com:443", "gh_config_dir", "error"},
		{"userinfo", "user@github.com", "gh_config_dir", "error"},
		{"wildcard", "*.example.com", "gh_config_dir", "error"},
		{"empty label", "github..com", "gh_config_dir", "error"},
		{"trailing dot", "github.com.", "gh_config_dir", "error"},
		{"leading hyphen", "-github.com", "gh_config_dir", "error"},
		{"trailing hyphen", "github-.com", "gh_config_dir", "error"},
		{"long label", strings.Repeat("a", 64) + ".com", "gh_config_dir", "error"},
		{"long host", strings.Repeat(strings.Repeat("a", 63)+".", 4) + "com", "gh_config_dir", "error"},
		{"GitLab", "github.com", "glab_config_dir", "error"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			contents := fmt.Sprintf("forge_profiles:\n  api-gateway.example:\n    %s: %q\n    github_web_host: %q\n", tc.provider, t.TempDir(), tc.host)
			cfg, err := LoadGlobalFromBytes([]byte(contents))
			if tc.want == "error" {
				if err == nil || !strings.Contains(err.Error(), "github_web_host") {
					t.Fatalf("LoadGlobalFromBytes error = %v, want github_web_host refusal", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got := cfg.ForgeProfiles["api-gateway.example"].GitHubWebHost; got != tc.want {
				t.Fatalf("GitHubWebHost = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestGitHubWebHostCannotBeOverriddenByRepoConfig(t *testing.T) {
	t.Parallel()
	global := &GlobalConfig{ForgeProfiles: ForgeProfiles{
		"api-gateway.example": {GHConfigDir: t.TempDir(), GitHubWebHost: "github.com"},
	}}
	repo, err := LoadRepoFromBytes([]byte("forge_profiles:\n  api-gateway.example:\n    gh_config_dir: /untrusted\n    github_web_host: attacker.example\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got := Merge(global, repo).ForgeProfiles["api-gateway.example"]; got != global.ForgeProfiles["api-gateway.example"] {
		t.Fatalf("repository changed machine-local forge identity: %+v", got)
	}
}

func TestLoadGlobalParsesProviderSpecificForgeProfiles(t *testing.T) {
	githubDir := filepath.Join(t.TempDir(), "gh-personal")
	gitlabDir := filepath.Join(t.TempDir(), "glab-work")
	path := filepath.Join(t.TempDir(), "config.yaml")
	contents := "forge_profiles:\n" +
		"  GitHub-Personal:\n" +
		"    gh_config_dir: " + githubDir + "\n" +
		"  gitlab-work:\n" +
		"    glab_config_dir: " + gitlabDir + "\n"
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadGlobal(path)
	if err != nil {
		t.Fatalf("LoadGlobal: %v", err)
	}

	if got := cfg.ForgeProfiles["github-personal"].GHConfigDir; got != githubDir {
		t.Fatalf("GitHub config dir = %q, want %q", got, githubDir)
	}
	if got := cfg.ForgeProfiles["gitlab-work"].GLabConfigDir; got != gitlabDir {
		t.Fatalf("GitLab config dir = %q, want %q", got, gitlabDir)
	}
}

func TestLoadGlobalPreservesAbsentAndEmptyForgeProfiles(t *testing.T) {
	for _, contents := range []string{"agent: auto\n", "forge_profiles: {}\n"} {
		path := filepath.Join(t.TempDir(), "config.yaml")
		if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
			t.Fatal(err)
		}
		cfg, err := LoadGlobal(path)
		if err != nil {
			t.Fatalf("LoadGlobal(%q): %v", contents, err)
		}
		if len(cfg.ForgeProfiles) != 0 {
			t.Fatalf("ForgeProfiles = %#v, want empty", cfg.ForgeProfiles)
		}
	}
}

func TestLoadGlobalRejectsUnknownForgeProfileField(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	contents := "forge_profiles:\n  github.com:\n    gh_config_dir: /tmp/gh\n    token: forbidden\n"
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadGlobal(path); err == nil || !strings.Contains(err.Error(), "token") {
		t.Fatalf("LoadGlobal error = %v, want unknown-field error", err)
	}
}

func TestLoadGlobalRejectsForgeProfileWithoutExactlyOneProvider(t *testing.T) {
	for _, tc := range []struct {
		name    string
		profile string
	}{
		{name: "neither", profile: "{}"},
		{name: "both", profile: "{gh_config_dir: /tmp/gh, glab_config_dir: /tmp/glab}"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			contents := "forge_profiles:\n  github-personal: " + tc.profile + "\n"
			if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
				t.Fatal(err)
			}

			_, err := LoadGlobal(path)
			if err == nil || !strings.Contains(err.Error(), "exactly one") {
				t.Fatalf("LoadGlobal error = %v, want exactly-one-provider error", err)
			}
		})
	}
}

func TestLoadGlobalExpandsHomeRelativeForgeProfilePath(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("forge_profiles:\n  github-personal:\n    gh_config_dir: ~/profiles/gh-personal\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadGlobal(path)
	if err != nil {
		t.Fatalf("LoadGlobal: %v", err)
	}
	if got, want := cfg.ForgeProfiles["github-personal"].GHConfigDir, filepath.Join(home, "profiles", "gh-personal"); got != want {
		t.Fatalf("GitHub config dir = %q, want %q", got, want)
	}
}

func TestLoadGlobalRejectsNonAbsoluteForgeProfilePath(t *testing.T) {
	for _, value := range []string{"profiles/gh", "$HOME/profiles/gh", "${HOME}/profiles/gh", "~someone/profiles/gh"} {
		t.Run(value, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			contents := "forge_profiles:\n  github-personal:\n    gh_config_dir: " + value + "\n"
			if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
				t.Fatal(err)
			}

			_, err := LoadGlobal(path)
			if err == nil || !strings.Contains(err.Error(), "absolute or start with ~/") {
				t.Fatalf("LoadGlobal error = %v, want absolute-path error", err)
			}
		})
	}
}

func TestLoadGlobalRejectsCaseInsensitiveDuplicateForgeHosts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	one := filepath.Join(t.TempDir(), "one")
	two := filepath.Join(t.TempDir(), "two")
	contents := "forge_profiles:\n" +
		"  GitHub-Personal:\n" +
		"    gh_config_dir: " + one + "\n" +
		"  github-personal:\n" +
		"    gh_config_dir: " + two + "\n"
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := LoadGlobal(path)
	if err == nil || !strings.Contains(err.Error(), "duplicate host") {
		t.Fatalf("LoadGlobal error = %v, want duplicate-host error", err)
	}
}

func TestLoadGlobalRejectsEmptyForgeHost(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("forge_profiles:\n  '':\n    gh_config_dir: /tmp/gh\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := LoadGlobal(path)
	if err == nil || !strings.Contains(err.Error(), "host must not be empty") {
		t.Fatalf("LoadGlobal error = %v, want empty-host error", err)
	}
}
