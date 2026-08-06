package github

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"

	"github.com/kunchenguid/no-mistakes/internal/scm"
)

const (
	actionsHeadA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	actionsHeadB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

func TestChecksPermissionFailureDoesNotFallBackToActions(t *testing.T) {
	t.Parallel()

	host := New(githubTestCmdFactory(map[string]githubTestResponse{
		"gh pr checks 42 --repo base/repo --json name,state,bucket,completedAt,link": {
			stderr: "GraphQL: Resource not accessible by personal access token",
			code:   1,
		},
	}), nil, "", "base/repo")

	checks, err := host.GetChecks(context.Background(), &scm.PR{Number: "42"})
	if err == nil {
		t.Fatal("GetChecks() error = nil, want the complete rollup permission failure")
	}
	if checks != nil {
		t.Fatalf("GetChecks() checks = %+v, want nil when the default observer cannot read the complete rollup", checks)
	}
	if !strings.Contains(err.Error(), "gh pr checks") {
		t.Fatalf("GetChecks() error = %v, want the unchanged rollup observer error", err)
	}
}

func TestActionsOnlyVisibilityBoundaryLeavesExternalChecksToDefaultObserver(t *testing.T) {
	t.Parallel()

	defaultHost := New(githubTestCmdFactory(map[string]githubTestResponse{
		"gh pr checks 42 --repo base/repo --json name,state,bucket,completedAt,link": {
			stdout: `[{"name":"security-app","state":"FAILURE","bucket":"fail","link":"https://security.example/check/7"}]`,
		},
	}), nil, "", "base/repo")
	checks, err := defaultHost.GetChecks(context.Background(), &scm.PR{Number: "42"})
	if err != nil {
		t.Fatalf("default GetChecks() error = %v", err)
	}
	if len(checks) != 1 || checks[0].Bucket != scm.CheckBucketFail {
		t.Fatalf("default GetChecks() = %+v, want the external App check from the complete rollup", checks)
	}

	actionsHost := NewWithOptions(githubTestCmdFactory(map[string]githubTestResponse{
		actionsPRCommand("base/repo", "42"):           {stdout: actionsPRPayload(actionsHeadA, "contributor/repo", "base/repo")},
		actionsRunsCommand("base/repo", actionsHeadA): {stdout: `[{"total_count":0,"workflow_runs":[]}]`},
	}), nil, "", "base/repo", Options{ActionsOnly: true})
	checks, err = actionsHost.GetChecks(context.Background(), &scm.PR{Number: "42"})
	if err != nil {
		t.Fatalf("Actions-only GetChecks() error = %v", err)
	}
	if len(checks) != 0 {
		t.Fatalf("Actions-only GetChecks() = %+v, want no claim of external CheckRun visibility", checks)
	}
}

func TestActionsObserverDistinguishesProviderFailureFromObservationError(t *testing.T) {
	t.Parallel()

	t.Run("provider-reported failure is check evidence", func(t *testing.T) {
		host := NewWithOptions(githubTestCmdFactory(map[string]githubTestResponse{
			actionsPRCommand("base/repo", "42"):           {stdout: actionsPRPayload(actionsHeadA, "contributor/repo", "base/repo")},
			actionsRunsCommand("base/repo", actionsHeadA): {stdout: singleActionsRun(actionsHeadA, "failure", "pull_request")},
			actionsJobsCommand("base/repo", 101):          {stdout: singleActionsJob(actionsHeadA, "failure")},
		}), nil, "", "base/repo", Options{ActionsOnly: true})

		checks, err := host.GetChecks(context.Background(), &scm.PR{Number: "42"})
		if err != nil {
			t.Fatalf("GetChecks() error = %v, want a provider-reported failed check", err)
		}
		if len(checks) != 1 || checks[0].Bucket != scm.CheckBucketFail || checks[0].State != "FAILURE" {
			t.Fatalf("GetChecks() = %+v, want failed Actions evidence", checks)
		}
	})

	t.Run("transport failure is observation error", func(t *testing.T) {
		host := NewWithOptions(githubTestCmdFactory(map[string]githubTestResponse{
			actionsPRCommand("base/repo", "42"):           {stdout: actionsPRPayload(actionsHeadA, "contributor/repo", "base/repo")},
			actionsRunsCommand("base/repo", actionsHeadA): {stderr: "Actions API unavailable", code: 1},
		}), nil, "", "base/repo", Options{ActionsOnly: true})

		checks, err := host.GetChecks(context.Background(), &scm.PR{Number: "42"})
		if err == nil {
			t.Fatal("GetChecks() error = nil, want transport failure")
		}
		if checks != nil {
			t.Fatalf("GetChecks() = %+v, want no check evidence from a failed observation", checks)
		}
	})
}

func TestActionsObserverEnumeratesExactHeadMultipleWorkflowsAndMatrixJobs(t *testing.T) {
	t.Parallel()

	host := NewWithOptions(githubTestCmdFactory(map[string]githubTestResponse{
		actionsPRCommand("base/repo", "42"): {
			stdout: actionsPRPayload(actionsHeadA, "contributor/repo", "base/repo"),
		},
		actionsRunsCommand("base/repo", actionsHeadA): {
			stdout: `[{"total_count":2,"workflow_runs":[
				{"id":101,"workflow_id":11,"run_attempt":1,"name":"CI","event":"pull_request","status":"completed","conclusion":"success","head_sha":"` + actionsHeadA + `","created_at":"2026-08-06T10:00:00Z","updated_at":"2026-08-06T10:05:00Z","repository":{"full_name":"base/repo"}},
				{"id":102,"workflow_id":12,"run_attempt":1,"name":"Guard","event":"push","status":"completed","conclusion":"success","head_sha":"` + actionsHeadA + `","created_at":"2026-08-06T10:01:00Z","updated_at":"2026-08-06T10:04:00Z","repository":{"full_name":"base/repo"}}
			]}]`,
		},
		actionsJobsCommand("base/repo", 101): {
			stdout: `[{"total_count":2,"jobs":[
				{"id":1001,"run_id":101,"name":"test (linux)","status":"completed","conclusion":"success","head_sha":"` + actionsHeadA + `","completed_at":"2026-08-06T10:03:00Z"},
				{"id":1002,"run_id":101,"name":"test (windows)","status":"completed","conclusion":"success","head_sha":"` + actionsHeadA + `","completed_at":"2026-08-06T10:05:00Z"}
			]}]`,
		},
		actionsJobsCommand("base/repo", 102): {
			stdout: `[{"total_count":1,"jobs":[
				{"id":1003,"run_id":102,"name":"optional deploy","status":"completed","conclusion":"skipped","head_sha":"` + actionsHeadA + `","completed_at":"2026-08-06T10:04:00Z"}
			]}]`,
		},
	}), nil, "", "base/repo", Options{ActionsOnly: true})

	checks, err := host.GetChecks(context.Background(), &scm.PR{Number: "42", URL: "https://github.com/base/repo/pull/42"})
	if err != nil {
		t.Fatalf("GetChecks() error = %v", err)
	}
	if len(checks) != 3 {
		t.Fatalf("GetChecks() returned %d checks, want all 3 matrix/workflow jobs: %+v", len(checks), checks)
	}
	want := map[string]scm.CheckBucket{
		"test (linux)": scm.CheckBucketPass, "test (windows)": scm.CheckBucketPass,
		"optional deploy": scm.CheckBucketSkip,
	}
	for _, check := range checks {
		if check.Bucket != want[check.Name] {
			t.Errorf("check %q bucket = %q, want %q", check.Name, check.Bucket, want[check.Name])
		}
		if !strings.HasPrefix(check.Link, "https://github.com/base/repo/actions/runs/") {
			t.Errorf("check %q link = %q, want base-repository Actions identity", check.Name, check.Link)
		}
	}
}

func TestNormalizeActionsState(t *testing.T) {
	t.Parallel()

	ptr := func(value string) *string { return &value }
	tests := []struct {
		name       string
		status     string
		conclusion *string
		wantBucket scm.CheckBucket
		wantState  string
	}{
		{name: "success", status: "completed", conclusion: ptr("success"), wantBucket: scm.CheckBucketPass, wantState: "SUCCESS"},
		{name: "failure", status: "completed", conclusion: ptr("failure"), wantBucket: scm.CheckBucketFail, wantState: "FAILURE"},
		{name: "error", status: "completed", conclusion: ptr("error"), wantBucket: scm.CheckBucketFail, wantState: "ERROR"},
		{name: "timed out", status: "completed", conclusion: ptr("timed_out"), wantBucket: scm.CheckBucketFail, wantState: "TIMED_OUT"},
		{name: "action required", status: "completed", conclusion: ptr("action_required"), wantBucket: scm.CheckBucketFail, wantState: "ACTION_REQUIRED"},
		{name: "startup failure", status: "completed", conclusion: ptr("startup_failure"), wantBucket: scm.CheckBucketFail, wantState: "STARTUP_FAILURE"},
		{name: "cancelled", status: "completed", conclusion: ptr("cancelled"), wantBucket: scm.CheckBucketCancel, wantState: "CANCELLED"},
		{name: "skipped", status: "completed", conclusion: ptr("skipped"), wantBucket: scm.CheckBucketSkip, wantState: "SKIPPED"},
		{name: "neutral", status: "completed", conclusion: ptr("neutral"), wantBucket: scm.CheckBucketSkip, wantState: "NEUTRAL"},
		{name: "stale", status: "completed", conclusion: ptr("stale"), wantBucket: scm.CheckBucketSkip, wantState: "STALE"},
		{name: "queued", status: "queued", wantBucket: scm.CheckBucketPending, wantState: "QUEUED"},
		{name: "in progress", status: "in_progress", wantBucket: scm.CheckBucketPending, wantState: "IN_PROGRESS"},
		{name: "waiting", status: "waiting", wantBucket: scm.CheckBucketPending, wantState: "WAITING"},
		{name: "requested", status: "requested", wantBucket: scm.CheckBucketPending, wantState: "REQUESTED"},
		{name: "pending", status: "pending", wantBucket: scm.CheckBucketPending, wantState: "PENDING"},
		{name: "expected", status: "expected", wantBucket: scm.CheckBucketPending, wantState: "EXPECTED"},
		{name: "completed null conclusion", status: "completed", wantBucket: scm.CheckBucketPending, wantState: "COMPLETED"},
		{name: "future conclusion", status: "completed", conclusion: ptr("teleported"), wantBucket: scm.CheckBucketPending, wantState: "TELEPORTED"},
		{name: "future status", status: "materializing", wantBucket: scm.CheckBucketPending, wantState: "MATERIALIZING"},
		{name: "future status ignores stale success conclusion", status: "materializing", conclusion: ptr("success"), wantBucket: scm.CheckBucketPending, wantState: "MATERIALIZING"},
		{name: "pending status ignores stale success conclusion", status: "in_progress", conclusion: ptr("success"), wantBucket: scm.CheckBucketPending, wantState: "IN_PROGRESS"},
		{name: "empty", status: "", wantBucket: scm.CheckBucketPending, wantState: "UNKNOWN"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			bucket, state := normalizeActionsState(tc.status, tc.conclusion)
			if bucket != tc.wantBucket || state != tc.wantState {
				t.Fatalf("normalizeActionsState(%q, %v) = (%q, %q), want (%q, %q)", tc.status, tc.conclusion, bucket, state, tc.wantBucket, tc.wantState)
			}
		})
	}
}

func TestParseActionsRunPagesCompleteness(t *testing.T) {
	t.Parallel()

	makeRun := func(id int) map[string]any {
		return map[string]any{
			"id": id, "workflow_id": id + 1000, "run_attempt": 1, "name": fmt.Sprintf("workflow-%d", id),
			"event": "push", "status": "completed", "conclusion": "success", "head_sha": actionsHeadA,
			"created_at": "2026-08-06T10:00:00Z", "updated_at": "2026-08-06T10:01:00Z",
			"repository": map[string]any{"full_name": "base/repo"},
		}
	}
	runs := make([]map[string]any, 101)
	for i := range runs {
		runs[i] = makeRun(i + 1)
	}
	complete, err := json.Marshal([]map[string]any{
		{"total_count": 101, "workflow_runs": runs[:100]},
		{"total_count": 101, "workflow_runs": runs[100:]},
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := parseActionsRunPages(complete, actionsHeadA, "base/repo")
	if err != nil || len(got) != 101 {
		t.Fatalf("parseActionsRunPages() = %d runs, %v; want 101 complete paginated runs", len(got), err)
	}

	cases := []struct {
		name    string
		pages   any
		wantErr string
	}{
		{name: "no pages", pages: []any{}, wantErr: "no pages"},
		{name: "truncated", pages: []any{map[string]any{"total_count": 2, "workflow_runs": []any{makeRun(1)}}}, wantErr: "want 2"},
		{name: "inconsistent totals", pages: []any{
			map[string]any{"total_count": 2, "workflow_runs": []any{makeRun(1)}},
			map[string]any{"total_count": 3, "workflow_runs": []any{makeRun(2)}},
		}, wantErr: "total_count"},
		{name: "duplicate run id", pages: []any{map[string]any{"total_count": 2, "workflow_runs": []any{makeRun(1), makeRun(1)}}}, wantErr: "more than once"},
		{name: "search cap", pages: []any{map[string]any{"total_count": 1000, "workflow_runs": []any{}}}, wantErr: "1,000-result"},
		{name: "wrong head", pages: []any{map[string]any{"total_count": 1, "workflow_runs": []any{func() map[string]any {
			run := makeRun(1)
			run["head_sha"] = actionsHeadB
			return run
		}()}}}, wantErr: "different head"},
		{name: "wrong repository", pages: []any{map[string]any{"total_count": 1, "workflow_runs": []any{func() map[string]any {
			run := makeRun(1)
			run["repository"] = map[string]any{"full_name": "other/repo"}
			return run
		}()}}}, wantErr: "different repository"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data, err := json.Marshal(tc.pages)
			if err != nil {
				t.Fatal(err)
			}
			_, err = parseActionsRunPages(data, actionsHeadA, "base/repo")
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("parseActionsRunPages() error = %v, want containing %q", err, tc.wantErr)
			}
		})
	}
}

func TestParseActionsJobPagesCompleteness(t *testing.T) {
	t.Parallel()
	makeJob := func(id int) map[string]any {
		return map[string]any{
			"id": id, "run_id": 99, "name": fmt.Sprintf("job-%d", id), "status": "completed",
			"conclusion": "success", "head_sha": actionsHeadA,
		}
	}
	largeJobs := make([]map[string]any, 101)
	for i := range largeJobs {
		largeJobs[i] = makeJob(i + 1)
	}
	largePages, err := json.Marshal([]map[string]any{
		{"total_count": 101, "jobs": largeJobs[:100]},
		{"total_count": 101, "jobs": largeJobs[100:]},
	})
	if err != nil {
		t.Fatal(err)
	}
	large, err := parseActionsJobPages(largePages, 99, actionsHeadA)
	if err != nil || len(large) != 101 {
		t.Fatalf("parseActionsJobPages() = %d jobs, %v; want 101 complete paginated jobs", len(large), err)
	}

	complete := []byte(`[
		{"total_count":2,"jobs":[{"id":1,"run_id":99,"name":"first","status":"completed","conclusion":"success","head_sha":"` + actionsHeadA + `"}]},
		{"total_count":2,"jobs":[{"id":2,"run_id":99,"name":"second","status":"completed","conclusion":"success","head_sha":"` + actionsHeadA + `"}]}
	]`)
	jobs, err := parseActionsJobPages(complete, 99, actionsHeadA)
	if err != nil || len(jobs) != 2 {
		t.Fatalf("parseActionsJobPages() = %d jobs, %v; want two complete pages", len(jobs), err)
	}

	cases := []struct {
		name    string
		data    string
		wantErr string
	}{
		{name: "truncated", data: `[{"total_count":2,"jobs":[{"id":1,"run_id":99,"name":"one","status":"completed","conclusion":"success","head_sha":"` + actionsHeadA + `"}]}]`, wantErr: "want 2"},
		{name: "duplicate", data: `[{"total_count":2,"jobs":[{"id":1,"run_id":99,"name":"one","status":"completed","conclusion":"success","head_sha":"` + actionsHeadA + `"},{"id":1,"run_id":99,"name":"again","status":"completed","conclusion":"success","head_sha":"` + actionsHeadA + `"}]}]`, wantErr: "more than once"},
		{name: "wrong run", data: `[{"total_count":1,"jobs":[{"id":1,"run_id":100,"name":"one","status":"completed","conclusion":"success","head_sha":"` + actionsHeadA + `"}]}]`, wantErr: "different run"},
		{name: "wrong head", data: `[{"total_count":1,"jobs":[{"id":1,"run_id":99,"name":"one","status":"completed","conclusion":"success","head_sha":"` + actionsHeadB + `"}]}]`, wantErr: "different head"},
		{name: "missing name", data: `[{"total_count":1,"jobs":[{"id":1,"run_id":99,"name":"","status":"completed","conclusion":"success","head_sha":"` + actionsHeadA + `"}]}]`, wantErr: "without a name"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseActionsJobPages([]byte(tc.data), 99, actionsHeadA)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("parseActionsJobPages() error = %v, want containing %q", err, tc.wantErr)
			}
		})
	}
}

func TestActionsOnlyRerunRejectsUnqualifiedLinks(t *testing.T) {
	t.Parallel()

	host := NewWithOptions(failIfInvokedCmdFactory(t), nil, "", "base/repo", Options{ActionsOnly: true})
	for _, link := range []string{
		"https://ci.example.com/base/repo/actions/runs/101/job/1001",
		"https://github.com/other/repo/actions/runs/101/job/1001",
	} {
		err := host.RerunCheck(context.Background(), &scm.PR{Number: "42"}, scm.Check{
			Name: "hostile", State: "CANCELLED", Bucket: scm.CheckBucketCancel, Link: link,
		})
		if err == nil {
			t.Fatalf("RerunCheck(%q) error = nil, want fail closed", link)
		}
	}
}

func TestActionsObserverZeroJobAndUnsupportedTriggerSemanticsFailClosed(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		event      string
		status     string
		conclusion string
		jobs       string
		want       scm.CheckBucket
	}{
		{name: "terminal failure without jobs", event: "pull_request", status: "completed", conclusion: "failure", jobs: `[{"total_count":0,"jobs":[]}]`, want: scm.CheckBucketFail},
		{name: "terminal success without jobs stays unresolved", event: "pull_request", status: "completed", conclusion: "success", jobs: `[{"total_count":0,"jobs":[]}]`, want: scm.CheckBucketPending},
		{name: "pending run before jobs register", event: "push", status: "queued", jobs: `[{"total_count":0,"jobs":[]}]`, want: scm.CheckBucketPending},
		{name: "pull request target is unsupported", event: "pull_request_target", status: "completed", conclusion: "success", jobs: `[{"total_count":1,"jobs":[{"id":1001,"run_id":101,"name":"target","status":"completed","conclusion":"success","head_sha":"` + actionsHeadA + `"}]}]`, want: scm.CheckBucketPending},
		{name: "merge group is a distinct target", event: "merge_group", status: "completed", conclusion: "success", jobs: `[{"total_count":1,"jobs":[{"id":1001,"run_id":101,"name":"queue","status":"completed","conclusion":"success","head_sha":"` + actionsHeadA + `"}]}]`, want: scm.CheckBucketPending},
		{name: "future trigger semantics are unsupported", event: "quantum_event", status: "completed", conclusion: "success", jobs: `[{"total_count":1,"jobs":[{"id":1001,"run_id":101,"name":"future","status":"completed","conclusion":"success","head_sha":"` + actionsHeadA + `"}]}]`, want: scm.CheckBucketPending},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			conclusion := "null"
			if tc.conclusion != "" {
				conclusion = fmt.Sprintf("%q", tc.conclusion)
			}
			host := NewWithOptions(githubTestCmdFactory(map[string]githubTestResponse{
				actionsPRCommand("base/repo", "42"):           {stdout: actionsPRPayload(actionsHeadA, "contributor/repo", "base/repo")},
				actionsRunsCommand("base/repo", actionsHeadA): {stdout: `[{"total_count":1,"workflow_runs":[{"id":101,"workflow_id":11,"run_attempt":1,"name":"CI","event":"` + tc.event + `","status":"` + tc.status + `","conclusion":` + conclusion + `,"head_sha":"` + actionsHeadA + `","created_at":"2026-08-06T10:00:00Z","updated_at":"2026-08-06T10:05:00Z","repository":{"full_name":"base/repo"}}]}]`},
				actionsJobsCommand("base/repo", 101):          {stdout: tc.jobs},
			}), nil, "", "base/repo", Options{ActionsOnly: true})

			checks, err := host.GetChecks(context.Background(), &scm.PR{Number: "42"})
			if err != nil {
				t.Fatalf("GetChecks() error = %v", err)
			}
			found := false
			for _, check := range checks {
				if check.Bucket == tc.want {
					found = true
				}
			}
			if !found {
				t.Fatalf("checks = %+v, want conservative %q result", checks, tc.want)
			}
		})
	}
}

func TestActionsObserverRetriesWhenPRHeadMoves(t *testing.T) {
	t.Parallel()

	headCommand := actionsPRCommand("base/repo", "42")
	responses := map[string][]githubTestResponse{
		headCommand: {
			{stdout: actionsPRPayload(actionsHeadA, "contributor/repo", "base/repo")},
			{stdout: actionsPRPayload(actionsHeadB, "contributor/repo", "base/repo")},
			{stdout: actionsPRPayload(actionsHeadB, "contributor/repo", "base/repo")},
			{stdout: actionsPRPayload(actionsHeadB, "contributor/repo", "base/repo")},
		},
		actionsRunsCommand("base/repo", actionsHeadA): {{stdout: singleActionsRun(actionsHeadA, "failure", "pull_request")}},
		actionsRunsCommand("base/repo", actionsHeadB): {{stdout: singleActionsRun(actionsHeadB, "success", "pull_request")}},
	}
	// The jobs command is identical across attempts, so return the old failed
	// job first and the new successful job second. The moved-head observation
	// must be discarded rather than leaking the first failure into the result.
	responses[actionsJobsCommand("base/repo", 101)] = []githubTestResponse{
		{stdout: singleActionsJob(actionsHeadA, "failure")},
		{stdout: singleActionsJob(actionsHeadB, "success")},
	}

	host := NewWithOptions(sequencedGithubTestCmdFactory(responses), nil, "", "base/repo", Options{ActionsOnly: true})
	checks, err := host.GetChecks(context.Background(), &scm.PR{Number: "42"})
	if err != nil {
		t.Fatalf("GetChecks() error = %v", err)
	}
	if len(checks) != 1 || checks[0].Bucket != scm.CheckBucketPass {
		t.Fatalf("GetChecks() = %+v, want only the retried new-head success", checks)
	}
}

func TestActionsObserverUsesLatestAttemptJobsAndPreservesRerunIdentity(t *testing.T) {
	t.Parallel()

	var recorded [][]string
	factory := recordingActionsCmdFactory(map[string]githubTestResponse{
		actionsPRCommand("base/repo", "42"):           {stdout: actionsPRPayload(actionsHeadA, "contributor/repo", "base/repo")},
		actionsRunsCommand("base/repo", actionsHeadA): {stdout: strings.Replace(singleActionsRun(actionsHeadA, "cancelled", "pull_request"), `"run_attempt":1`, `"run_attempt":2`, 1)},
		actionsJobsCommand("base/repo", 101):          {stdout: singleActionsJob(actionsHeadA, "cancelled")},
		"gh run rerun --job 1001 --repo base/repo":    {},
	}, &recorded)
	host := NewWithOptions(factory, nil, "", "base/repo", Options{ActionsOnly: true})

	checks, err := host.GetChecks(context.Background(), &scm.PR{Number: "42"})
	if err != nil {
		t.Fatalf("GetChecks() error = %v", err)
	}
	if len(checks) != 1 || checks[0].Bucket != scm.CheckBucketCancel {
		t.Fatalf("checks = %+v, want latest-attempt cancelled job", checks)
	}
	if err := host.RerunCheck(context.Background(), &scm.PR{Number: "42"}, checks[0]); err != nil {
		t.Fatalf("RerunCheck() error = %v", err)
	}
	if !strings.Contains(strings.Join(recordedCommandStrings(recorded), "\n"), "filter=latest") {
		t.Fatalf("recorded commands = %v, want latest-attempt jobs query", recorded)
	}
}

func TestActionsObserverRerunsWholeCancelledRunWhenNoJobExists(t *testing.T) {
	t.Parallel()

	host := NewWithOptions(githubTestCmdFactory(map[string]githubTestResponse{
		actionsPRCommand("base/repo", "42"):           {stdout: actionsPRPayload(actionsHeadA, "contributor/repo", "base/repo")},
		actionsRunsCommand("base/repo", actionsHeadA): {stdout: singleActionsRun(actionsHeadA, "cancelled", "pull_request")},
		actionsJobsCommand("base/repo", 101):          {stdout: `[{"total_count":0,"jobs":[]}]`},
		"gh run rerun 101 --repo base/repo":           {},
	}), nil, "", "base/repo", Options{ActionsOnly: true})

	checks, err := host.GetChecks(context.Background(), &scm.PR{Number: "42"})
	if err != nil {
		t.Fatalf("GetChecks() error = %v", err)
	}
	if len(checks) != 1 || checks[0].Bucket != scm.CheckBucketCancel {
		t.Fatalf("checks = %+v, want the cancelled run-level result", checks)
	}
	if err := host.RerunCheck(context.Background(), &scm.PR{Number: "42"}, checks[0]); err != nil {
		t.Fatalf("RerunCheck() error = %v", err)
	}
}

func TestActionsObserverZeroRunsReturnsNoChecksForTrustedNoCIHandling(t *testing.T) {
	t.Parallel()

	host := NewWithOptions(githubTestCmdFactory(map[string]githubTestResponse{
		actionsPRCommand("base/repo", "42"):           {stdout: actionsPRPayload(actionsHeadA, "contributor/repo", "base/repo")},
		actionsRunsCommand("base/repo", actionsHeadA): {stdout: `[{"total_count":0,"workflow_runs":[]}]`},
	}), nil, "", "base/repo", Options{ActionsOnly: true})

	checks, err := host.GetChecks(context.Background(), &scm.PR{Number: "42"})
	if err != nil || len(checks) != 0 {
		t.Fatalf("GetChecks() = %+v, %v, want empty evidence for the CI step's trusted no_ci decision", checks, err)
	}
}

func TestActionsObserverRequiresNumericPRAndExplicitBaseRepository(t *testing.T) {
	t.Parallel()

	host := NewWithOptions(failIfInvokedCmdFactory(t), nil, "", "", Options{ActionsOnly: true})
	if _, err := host.GetChecks(context.Background(), &scm.PR{Number: "branch-name"}); err == nil {
		t.Fatal("GetChecks() with non-numeric PR identity = nil error, want fail closed")
	}
	if _, err := host.GetChecks(context.Background(), &scm.PR{Number: "42"}); err == nil {
		t.Fatal("GetChecks() without an explicit base repository = nil error, want fail closed")
	}
}

func TestActionsObserverBoundsAndRedactsAPIErrors(t *testing.T) {
	t.Parallel()

	const secret = "fine-grained-secret"
	output := "https://token:" + secret + "@github.com/base/repo " + strings.Repeat("x", maxGitHubCommandOutput+500)
	host := NewWithOptions(githubTestCmdFactory(map[string]githubTestResponse{
		actionsPRCommand("base/repo", "42"):           {stdout: actionsPRPayload(actionsHeadA, "contributor/repo", "base/repo")},
		actionsRunsCommand("base/repo", actionsHeadA): {stderr: output, code: 1},
	}), nil, "", "base/repo", Options{ActionsOnly: true})

	_, err := host.GetChecks(context.Background(), &scm.PR{Number: "42"})
	if err == nil {
		t.Fatal("GetChecks() error = nil, want API failure")
	}
	message := err.Error()
	if strings.Contains(message, secret) || strings.Contains(message, "https://token:") {
		t.Fatalf("GetChecks() leaked credential in %q", message)
	}
	if !strings.Contains(message, "...[truncated]") {
		t.Fatalf("GetChecks() error was not bounded: %q", message)
	}
}

func actionsPRCommand(repo, number string) string {
	return "gh api --method GET repos/" + repo + "/pulls/" + number
}

func actionsRunsCommand(repo, head string) string {
	return "gh api --method GET repos/" + repo + "/actions/runs -f head_sha=" + head + " -f per_page=100 --paginate --slurp"
}

func actionsJobsCommand(repo string, runID int64) string {
	return fmt.Sprintf("gh api --method GET repos/%s/actions/runs/%d/jobs -f filter=latest -f per_page=100 --paginate --slurp", repo, runID)
}

func actionsPRPayload(head, headRepo, baseRepo string) string {
	return `{"head":{"sha":"` + head + `","repo":{"full_name":"` + headRepo + `"}},"base":{"repo":{"full_name":"` + baseRepo + `"}}}`
}

func singleActionsRun(head, conclusion, event string) string {
	return `[{"total_count":1,"workflow_runs":[{"id":101,"workflow_id":11,"run_attempt":1,"name":"CI","event":"` + event + `","status":"completed","conclusion":"` + conclusion + `","head_sha":"` + head + `","created_at":"2026-08-06T10:00:00Z","updated_at":"2026-08-06T10:05:00Z","repository":{"full_name":"base/repo"}}]}]`
}

func singleActionsJob(head, conclusion string) string {
	return `[{"total_count":1,"jobs":[{"id":1001,"run_id":101,"name":"test","status":"completed","conclusion":"` + conclusion + `","head_sha":"` + head + `","completed_at":"2026-08-06T10:05:00Z"}]}]`
}

func sequencedGithubTestCmdFactory(responses map[string][]githubTestResponse) CmdFactory {
	var mu sync.Mutex
	return func(ctx context.Context, name string, args ...string) *exec.Cmd {
		key := strings.TrimSpace(name + " " + strings.Join(args, " "))
		mu.Lock()
		sequence := responses[key]
		response := githubTestResponse{stderr: "unexpected command: " + key, code: 1}
		if len(sequence) > 0 {
			response = sequence[0]
			if len(sequence) > 1 {
				responses[key] = sequence[1:]
			}
		}
		mu.Unlock()
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=TestGitHubHelperProcess", "--", key)
		cmd.Env = append(os.Environ(),
			"GITHUB_TEST_HELPER=1",
			"GITHUB_TEST_STDOUT="+response.stdout,
			"GITHUB_TEST_STDERR="+response.stderr,
			fmt.Sprintf("GITHUB_TEST_EXIT_CODE=%d", response.code),
		)
		return cmd
	}
}

func recordingActionsCmdFactory(responses map[string]githubTestResponse, recorded *[][]string) CmdFactory {
	inner := githubTestCmdFactory(responses)
	return func(ctx context.Context, name string, args ...string) *exec.Cmd {
		*recorded = append(*recorded, append([]string{name}, args...))
		return inner(ctx, name, args...)
	}
}

func recordedCommandStrings(recorded [][]string) []string {
	out := make([]string, len(recorded))
	for i, args := range recorded {
		out[i] = strings.Join(args, " ")
	}
	return out
}
