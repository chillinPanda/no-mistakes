package steps

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kunchenguid/no-mistakes/internal/config"
	"github.com/kunchenguid/no-mistakes/internal/forgecontext"
)

// Exercise config -> run context -> provider -> existing PR update, not just
// the URL parser: the pre-push attestation must keep using gateway credentials.
func TestPRStep_CanonicalWebHostBehindAPIGateway(t *testing.T) {
	t.Parallel()
	dir, baseSHA, headSHA := setupGitRepo(t)
	profileDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(profileDir, "hosts.yml"), []byte("api-gateway.example:\n  user: contributor\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	global, err := config.LoadGlobalFromBytes([]byte(fmt.Sprintf("forge_profiles:\n  api-gateway.example:\n    gh_config_dir: %q\n    expected_login: contributor\n    github_web_host: github.com\n", profileDir)))
	if err != nil {
		t.Fatal(err)
	}
	env, logFile := fakeGH(t, "https://github.com/test/repo/pull/42")
	sctx := newTestContextWithDBRecords(t, &mockAgent{name: "test"}, dir, baseSHA, headSHA, config.Commands{})
	sctx.Env = env
	sctx.Repo.UpstreamURL = "https://api-gateway.example/test/repo.git"
	sctx.ForgeContext, err = forgecontext.Resolve(context.Background(), global.ForgeProfiles, sctx.Repo.UpstreamURL, "")
	if err != nil {
		t.Fatal(err)
	}
	outcome, err := (&PRStep{}).Execute(sctx)
	if err != nil || outcome.Skipped {
		t.Fatalf("PR step = %+v, %v, want canonical PR updated", outcome, err)
	}
	logData, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatal(err)
	}
	for _, command := range []string{
		"auth status --hostname api-gateway.example",
		"--repo api-gateway.example/test/repo",
		"api --hostname api-gateway.example --method PATCH repos/test/repo/pulls/42",
	} {
		if !strings.Contains(string(logData), command) {
			t.Fatalf("missing gateway command %q in:\n%s", command, logData)
		}
	}
	run, err := sctx.DB.GetRun(sctx.Run.ID)
	if err != nil {
		t.Fatal(err)
	}
	if run.PRURL == nil || *run.PRURL != "https://github.com/test/repo/pull/42" {
		t.Fatalf("stored PR URL = %v, want canonical browser URL", run.PRURL)
	}
}
