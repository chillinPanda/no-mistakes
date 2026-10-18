package github

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/kunchenguid/no-mistakes/internal/scm"
)

func TestFindPRCanonicalWebHost(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, webHost, url string
		wantError          bool
	}{
		{"public GitHub", "github.com", "https://github.com/acme/repo/pull/42", false},
		{"enterprise", "git.corp.example", "https://git.corp.example/acme/repo/pull/42", false},
		{"no mapping", "", "https://github.com/acme/repo/pull/42", true},
		{"legacy host", "", "https://api-gateway.example/acme/repo/pull/42", false},
		{"foreign host", "github.com", "https://attacker.example/acme/repo/pull/42", true},
		{"foreign repository", "github.com", "https://github.com/acme/other/pull/42", true},
		{"foreign PR number", "github.com", "https://github.com/acme/repo/pull/43", true},
		{"gateway web URL", "github.com", "https://api-gateway.example/acme/repo/pull/42", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := New(githubTestCmdFactory(map[string]githubTestResponse{
				"gh auth status --hostname api-gateway.example": {},
				"gh pr list --head feature --repo api-gateway.example/acme/repo --state open --json number,url,baseRefName": {
					stdout: fmt.Sprintf(`[{"number":42,"url":%q,"baseRefName":"main"}]`, tc.url),
				},
			}), nil, "api-gateway.example", "api-gateway.example/acme/repo")
			h.SetWebHost(tc.webHost)
			if err := h.Available(context.Background()); err != nil {
				t.Fatal(err)
			}
			pr, err := h.FindPR(context.Background(), "feature", "")
			if tc.wantError {
				if err == nil || pr != nil {
					t.Fatalf("FindPR = %+v, %v, want identity refusal", pr, err)
				}
				return
			}
			if err != nil || pr == nil || pr.URL != tc.url || pr.Number != "42" {
				t.Fatalf("FindPR = %+v, %v", pr, err)
			}
		})
	}
}

func TestFindPRCanonicalWebHostPreservesForkSelection(t *testing.T) {
	t.Parallel()
	h := NewWithFork(githubTestCmdFactory(map[string]githubTestResponse{
		"gh pr list --head feature --repo api-gateway.example/parent/repo --state open --json number,url,baseRefName,headRefName,headRepositoryOwner": {
			stdout: `[
				{"number":41,"url":"https://github.com/parent/repo/pull/41","baseRefName":"main","headRefName":"feature","headRepositoryOwner":{"login":"other"}},
				{"number":42,"url":"https://github.com/parent/repo/pull/42","baseRefName":"main","headRefName":"feature","headRepositoryOwner":{"login":"contributor"}}
			]`,
		},
	}), nil, "api-gateway.example", "api-gateway.example/parent/repo", "contributor/repo", false)
	h.SetWebHost("github.com")
	pr, err := h.FindPR(context.Background(), "feature", "")
	if err != nil || pr == nil || pr.Number != "42" {
		t.Fatalf("FindPR = %+v, %v, want contributor's parent PR", pr, err)
	}
}

func TestCanonicalWebHostKeepsReviewCommentsOnGateway(t *testing.T) {
	t.Parallel()
	command := "gh api --hostname api-gateway.example graphql -f query=" + reviewThreadsQuery + " -F owner=acme -F name=repo -F number=42"
	h := New(githubTestCmdFactory(map[string]githubTestResponse{
		command: {stdout: `{"data":{"repository":{"pullRequest":{"reviewThreads":{"nodes":[{"comments":{"nodes":[{"databaseId":7,"body":"Please handle the error","path":"main.go","line":8,"author":{"login":"greptile-apps[bot]"}}]}}],"pageInfo":{"hasNextPage":false}}}}}}`},
	}), nil, "api-gateway.example", "api-gateway.example/acme/repo")
	h.SetWebHost("github.com")
	comments, err := h.GetReviewComments(context.Background(), &scm.PR{URL: "https://github.com/acme/repo/pull/42"})
	if err != nil || len(comments) != 1 || comments[0].ID != "7" {
		t.Fatalf("GetReviewComments = %+v, %v", comments, err)
	}
}

func TestCanonicalWebHostActionsUseGateway(t *testing.T) {
	t.Parallel()
	for _, webHost := range []string{"github.com", "git.corp.example"} {
		t.Run(webHost, func(t *testing.T) {
			t.Parallel()
			h := New(githubTestCmdFactory(map[string]githubTestResponse{
				"gh api --hostname api-gateway.example --method GET repos/acme/repo/actions/runs -f head_sha=deadbeef -f per_page=100 --paginate --slurp": {
					stdout: `[{"total_count":1,"workflow_runs":[{"id":900,"name":"build","status":"completed","conclusion":"failure"}]}]`,
				},
				"gh run rerun --job 901 --repo api-gateway.example/acme/repo": {},
			}), nil, "api-gateway.example", "api-gateway.example/acme/repo")
			h.SetWebHost(webHost)
			checks, err := h.getWorkflowRunChecks(context.Background(), "deadbeef")
			wantURL := "https://" + webHost + "/acme/repo/actions/runs/900"
			if err != nil || len(checks) != 1 || checks[0].Link != wantURL {
				t.Fatalf("workflow checks = %+v, %v, want link %s", checks, err, wantURL)
			}
			err = h.RerunCheck(context.Background(), &scm.PR{Number: "42"}, scm.Check{Bucket: scm.CheckBucketFail, Link: wantURL + "/job/901?pr=42#step:1:1"})
			if err != nil {
				t.Fatal(err)
			}
			for _, link := range []string{
				"https://attacker.example/acme/repo/actions/runs/900/job/901",
				"https://api-gateway.example/acme/repo/actions/runs/900/job/901",
				"https://" + webHost + "/other/repo/actions/runs/900/job/901",
			} {
				refusing := New(failIfInvokedCmdFactory(t), nil, "api-gateway.example", "api-gateway.example/acme/repo")
				refusing.SetWebHost(webHost)
				if err := refusing.RerunCheck(context.Background(), &scm.PR{Number: "42"}, scm.Check{Bucket: scm.CheckBucketFail, Link: link}); err == nil {
					t.Fatalf("reran untrusted Actions link %s", link)
				}
			}
		})
	}
}

func TestCanonicalWebHostDoesNotEnableDirectUploads(t *testing.T) {
	t.Parallel()
	h := New(failIfInvokedCmdFactory(t), nil, "api-gateway.example", "api-gateway.example/acme/repo")
	h.SetWebHost("github.com")
	if _, err := h.UploadUserAsset(context.Background(), "evidence.png"); err == nil || !strings.Contains(err.Error(), "not supported") {
		t.Fatalf("UploadUserAsset error = %v, want refusal before reading credentials", err)
	}
}

func TestCanonicalWebHostURLSelectorsKeepGatewayRouting(t *testing.T) {
	t.Parallel()
	h := New(githubTestCmdFactory(map[string]githubTestResponse{
		"gh pr view 42 --repo api-gateway.example/acme/repo --json title,body":                    {stdout: `{"title":"Author title","body":"Author body"}`},
		"gh pr edit 42 --repo api-gateway.example/acme/repo --base release":                       {},
		"gh api --hostname api-gateway.example --method PATCH repos/acme/repo/pulls/42 --input -": {},
	}), nil, "api-gateway.example", "api-gateway.example/acme/repo")
	h.SetWebHost("github.com")
	pr := &scm.PR{URL: "https://github.com/acme/repo/pull/42"}
	content, err := h.GetPRContent(context.Background(), pr)
	if err != nil || content.Body != "Author body" {
		t.Fatalf("GetPRContent = %+v, %v", content, err)
	}
	if err := h.SetPRBaseBranch(context.Background(), pr, "release"); err != nil {
		t.Fatal(err)
	}
	if _, err := h.UpdatePR(context.Background(), pr, scm.PRContent{Body: "Updated body"}); err != nil {
		t.Fatal(err)
	}
	for _, foreign := range []*scm.PR{
		{URL: "https://attacker.example/acme/repo/pull/42"},
		{URL: "https://github.com/other/repo/pull/42"},
		{URL: "https://github.com/acme/repo/pull/42", Number: "43"},
	} {
		refusing := New(failIfInvokedCmdFactory(t), nil, "api-gateway.example", "api-gateway.example/acme/repo")
		refusing.SetWebHost("github.com")
		if _, err := refusing.GetPRContent(context.Background(), foreign); err == nil {
			t.Fatalf("read foreign PR %+v", foreign)
		}
	}
}

func TestCreatePRCanonicalWebHost(t *testing.T) {
	t.Parallel()
	for _, webHost := range []string{"github.com", "git.corp.example"} {
		for _, returnedHost := range []string{webHost, "attacker.example"} {
			t.Run(webHost+"/"+returnedHost, func(t *testing.T) {
				t.Parallel()
				h := NewWithFork(githubTestCmdFactory(map[string]githubTestResponse{
					"gh pr create --head contributor:feature --base main --repo api-gateway.example/parent/repo --title Title --body-file -": {
						stdout: "https://" + returnedHost + "/parent/repo/pull/42\n",
					},
				}), nil, "api-gateway.example", "api-gateway.example/parent/repo", "contributor/repo", false)
				h.SetWebHost(webHost)
				pr, err := h.CreatePR(context.Background(), "feature", "main", scm.PRContent{Title: "Title", Body: "Body"})
				if returnedHost != webHost {
					if err == nil || pr != nil {
						t.Fatalf("CreatePR = %+v, %v, want foreign web identity refused", pr, err)
					}
					return
				}
				if err != nil || pr == nil || pr.Number != "42" || pr.URL != "https://"+webHost+"/parent/repo/pull/42" {
					t.Fatalf("CreatePR = %+v, %v", pr, err)
				}
			})
		}
	}
}
