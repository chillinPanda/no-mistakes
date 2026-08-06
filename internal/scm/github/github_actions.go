package github

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/kunchenguid/no-mistakes/internal/safeurl"
	"github.com/kunchenguid/no-mistakes/internal/scm"
)

const (
	maxGitHubCommandOutput = 4096
	maxActionsHeadAttempts = 3
	maxActionsSearchRuns   = 1000
)

type actionsWorkflowRun struct {
	ID            int64   `json:"id"`
	WorkflowID    int64   `json:"workflow_id"`
	RunAttempt    int     `json:"run_attempt"`
	Name          string  `json:"name"`
	Event         string  `json:"event"`
	Status        string  `json:"status"`
	Conclusion    *string `json:"conclusion"`
	HeadSHA       string  `json:"head_sha"`
	CreatedAtRaw  string  `json:"created_at"`
	UpdatedAtRaw  string  `json:"updated_at"`
	RepositoryRaw *struct {
		FullName string `json:"full_name"`
	} `json:"repository"`

	createdAt time.Time
	updatedAt time.Time
}

type actionsWorkflowJob struct {
	ID             int64   `json:"id"`
	RunID          int64   `json:"run_id"`
	Name           string  `json:"name"`
	Status         string  `json:"status"`
	Conclusion     *string `json:"conclusion"`
	HeadSHA        string  `json:"head_sha"`
	CompletedAtRaw string  `json:"completed_at"`

	completedAt time.Time
}

// getActionsChecks implements the explicitly trusted Actions-only observer.
// It never calls the PR status rollup: that is the whole fine-grained-PAT
// permission boundary, and also why this narrower observer may only be selected
// by trusted default-branch configuration. Each attempt binds all evidence to
// one immutable PR head, then verifies the live head again before returning.
func (h *Host) getActionsChecks(ctx context.Context, pr *scm.PR) ([]scm.Check, error) {
	repo, err := h.actionsRepoSlug()
	if err != nil {
		return nil, err
	}
	prNumber, err := numericPRNumber(pr)
	if err != nil {
		return nil, err
	}

	var firstHead, lastHead string
	for attempt := 1; attempt <= maxActionsHeadAttempts; attempt++ {
		headSHA, err := h.getActionsPRHead(ctx, repo, prNumber)
		if err != nil {
			return nil, err
		}
		if firstHead == "" {
			firstHead = headSHA
		}
		checks, err := h.getActionsChecksAtHead(ctx, repo, headSHA)
		if err != nil {
			return nil, err
		}
		currentHead, err := h.getActionsPRHead(ctx, repo, prNumber)
		if err != nil {
			return nil, err
		}
		lastHead = currentHead
		if currentHead == headSHA {
			return checks, nil
		}
	}
	return nil, fmt.Errorf("GitHub PR head kept moving during Actions observation from %s to %s after %d attempts", firstHead, lastHead, maxActionsHeadAttempts)
}

func (h *Host) getActionsPRHead(ctx context.Context, repo, prNumber string) (string, error) {
	endpoint := "repos/" + repo + "/pulls/" + prNumber
	out, err := h.runGitHubAPI(ctx, endpoint)
	if err != nil {
		return "", err
	}
	var response struct {
		Head struct {
			SHA string `json:"sha"`
		} `json:"head"`
		Base struct {
			Repo *struct {
				FullName string `json:"full_name"`
			} `json:"repo"`
		} `json:"base"`
	}
	if err := json.Unmarshal(out, &response); err != nil {
		return "", fmt.Errorf("parse GitHub PR head: %w", err)
	}
	if response.Base.Repo == nil || !strings.EqualFold(strings.TrimSpace(response.Base.Repo.FullName), repo) {
		return "", fmt.Errorf("GitHub PR response named a different base repository %q, want %q", repoFullName(response.Base.Repo), repo)
	}
	headSHA := strings.ToLower(strings.TrimSpace(response.Head.SHA))
	if !validGitHubSHA(headSHA) {
		return "", fmt.Errorf("GitHub PR response returned malformed head SHA %q", headSHA)
	}
	return headSHA, nil
}

func repoFullName(repo *struct {
	FullName string `json:"full_name"`
}) string {
	if repo == nil {
		return ""
	}
	return strings.TrimSpace(repo.FullName)
}

func (h *Host) getActionsChecksAtHead(ctx context.Context, repo, headSHA string) ([]scm.Check, error) {
	runsEndpoint := "repos/" + repo + "/actions/runs"
	out, err := h.runGitHubAPIPaginated(ctx, runsEndpoint, "head_sha="+headSHA)
	if err != nil {
		return nil, err
	}
	runs, err := parseActionsRunPages(out, headSHA, repo)
	if err != nil {
		return nil, err
	}

	checks := make([]scm.Check, 0, len(runs))
	for _, run := range runs {
		jobsEndpoint := fmt.Sprintf("repos/%s/actions/runs/%d/jobs", repo, run.ID)
		jobOut, err := h.runGitHubAPIPaginated(ctx, jobsEndpoint, "filter=latest")
		if err != nil {
			return nil, err
		}
		jobs, err := parseActionsJobPages(jobOut, run.ID, headSHA)
		if err != nil {
			return nil, err
		}

		runChecks := make([]scm.Check, 0, len(jobs)+1)
		for _, job := range jobs {
			bucket, state := normalizeActionsState(job.Status, job.Conclusion)
			runChecks = append(runChecks, scm.Check{
				Name:        job.Name,
				Bucket:      bucket,
				State:       state,
				CompletedAt: job.completedAt,
				Link:        h.actionsJobURL(repo, run.ID, job.ID),
			})
		}

		runBucket, runState := normalizeActionsState(run.Status, run.Conclusion)
		unsupportedEvent := !actionsEventSupportsExactPRHead(run.Event)
		needRunCheck := unsupportedEvent || len(jobs) == 0 || !bucketRepresented(runChecks, runBucket)
		if len(jobs) > 0 && (runBucket == scm.CheckBucketPass || runBucket == scm.CheckBucketSkip) && !unsupportedEvent {
			// Successful/skipped workflow summaries add no evidence beyond their
			// jobs. Keep job-level identities for logs and targeted reruns.
			needRunCheck = false
		}
		if needRunCheck {
			if unsupportedEvent {
				runBucket = scm.CheckBucketPending
				runState = "UNSUPPORTED_EVENT_" + strings.ToUpper(run.Event)
			} else if len(jobs) == 0 && (runBucket == scm.CheckBucketPass || runBucket == scm.CheckBucketSkip) {
				// A terminal green/skip summary with no jobs gives no check-level
				// evidence and may reflect validation/registration gaps. Do not let
				// an empty job list certify the head.
				runBucket = scm.CheckBucketPending
				runState = "COMPLETED_WITHOUT_JOBS"
			}
			runChecks = append(runChecks, scm.Check{
				Name:        run.Name,
				Bucket:      runBucket,
				State:       runState,
				CompletedAt: run.updatedAt,
				Link:        h.actionsRunURL(repo, run.ID),
			})
		}
		checks = append(checks, runChecks...)
	}
	return checks, nil
}

func parseActionsRunPages(data []byte, headSHA, repo string) ([]actionsWorkflowRun, error) {
	var pages []struct {
		TotalCount   *int                 `json:"total_count"`
		WorkflowRuns []actionsWorkflowRun `json:"workflow_runs"`
	}
	if err := json.Unmarshal(data, &pages); err != nil {
		return nil, fmt.Errorf("parse GitHub Actions workflow-run pages: %w", err)
	}
	if len(pages) == 0 {
		return nil, errors.New("GitHub Actions workflow-run discovery returned no pages")
	}

	total := -1
	seen := make(map[int64]struct{})
	runs := make([]actionsWorkflowRun, 0)
	for pageIndex, page := range pages {
		if page.TotalCount == nil || *page.TotalCount < 0 {
			return nil, fmt.Errorf("GitHub Actions workflow-run page %d has no valid total_count", pageIndex+1)
		}
		if total == -1 {
			total = *page.TotalCount
			if total >= maxActionsSearchRuns {
				return nil, fmt.Errorf("GitHub Actions workflow-run search reached the 1,000-result API cap; completeness cannot be proven")
			}
		} else if *page.TotalCount != total {
			return nil, fmt.Errorf("GitHub Actions workflow-run page %d total_count is %d, want %d", pageIndex+1, *page.TotalCount, total)
		}
		for _, run := range page.WorkflowRuns {
			if run.ID <= 0 {
				return nil, fmt.Errorf("GitHub Actions workflow-run page %d contains a run without a valid id", pageIndex+1)
			}
			if _, ok := seen[run.ID]; ok {
				return nil, fmt.Errorf("GitHub Actions workflow run id %d appears more than once", run.ID)
			}
			seen[run.ID] = struct{}{}
			if err := validateActionsRun(&run, headSHA, repo); err != nil {
				return nil, err
			}
			runs = append(runs, run)
		}
	}
	if len(seen) != total {
		return nil, fmt.Errorf("GitHub Actions workflow-run discovery returned %d unique runs, want %d", len(seen), total)
	}
	return runs, nil
}

func validateActionsRun(run *actionsWorkflowRun, headSHA, repo string) error {
	if run.WorkflowID <= 0 || run.RunAttempt <= 0 {
		return fmt.Errorf("GitHub Actions workflow run %d has incomplete workflow/attempt identity", run.ID)
	}
	run.Name = strings.TrimSpace(run.Name)
	run.Event = strings.ToLower(strings.TrimSpace(run.Event))
	run.Status = strings.ToLower(strings.TrimSpace(run.Status))
	if run.Name == "" || run.Event == "" || run.Status == "" {
		return fmt.Errorf("GitHub Actions workflow run %d has incomplete name, event, or status", run.ID)
	}
	if !strings.EqualFold(strings.TrimSpace(run.HeadSHA), headSHA) {
		return fmt.Errorf("GitHub Actions workflow run %d belongs to a different head %q, want %q", run.ID, run.HeadSHA, headSHA)
	}
	if run.RepositoryRaw == nil || !strings.EqualFold(strings.TrimSpace(run.RepositoryRaw.FullName), repo) {
		got := ""
		if run.RepositoryRaw != nil {
			got = run.RepositoryRaw.FullName
		}
		return fmt.Errorf("GitHub Actions workflow run %d belongs to a different repository %q, want %q", run.ID, got, repo)
	}
	createdAt, err := time.Parse(time.RFC3339, strings.TrimSpace(run.CreatedAtRaw))
	if err != nil {
		return fmt.Errorf("GitHub Actions workflow run %d has malformed created_at: %w", run.ID, err)
	}
	updatedAt, err := time.Parse(time.RFC3339, strings.TrimSpace(run.UpdatedAtRaw))
	if err != nil {
		return fmt.Errorf("GitHub Actions workflow run %d has malformed updated_at: %w", run.ID, err)
	}
	if updatedAt.Before(createdAt) {
		return fmt.Errorf("GitHub Actions workflow run %d updated_at precedes created_at", run.ID)
	}
	run.createdAt, run.updatedAt = createdAt, updatedAt
	return nil
}

func parseActionsJobPages(data []byte, runID int64, headSHA string) ([]actionsWorkflowJob, error) {
	var pages []struct {
		TotalCount *int                 `json:"total_count"`
		Jobs       []actionsWorkflowJob `json:"jobs"`
	}
	if err := json.Unmarshal(data, &pages); err != nil {
		return nil, fmt.Errorf("parse GitHub Actions job pages for run %d: %w", runID, err)
	}
	if len(pages) == 0 {
		return nil, fmt.Errorf("GitHub Actions job discovery for run %d returned no pages", runID)
	}

	total := -1
	seen := make(map[int64]struct{})
	jobs := make([]actionsWorkflowJob, 0)
	for pageIndex, page := range pages {
		if page.TotalCount == nil || *page.TotalCount < 0 {
			return nil, fmt.Errorf("GitHub Actions job page %d for run %d has no valid total_count", pageIndex+1, runID)
		}
		if total == -1 {
			total = *page.TotalCount
		} else if *page.TotalCount != total {
			return nil, fmt.Errorf("GitHub Actions job page %d for run %d total_count is %d, want %d", pageIndex+1, runID, *page.TotalCount, total)
		}
		for _, job := range page.Jobs {
			if job.ID <= 0 {
				return nil, fmt.Errorf("GitHub Actions job page %d for run %d contains a job without a valid id", pageIndex+1, runID)
			}
			if _, ok := seen[job.ID]; ok {
				return nil, fmt.Errorf("GitHub Actions job id %d appears more than once", job.ID)
			}
			seen[job.ID] = struct{}{}
			if job.RunID != runID {
				return nil, fmt.Errorf("GitHub Actions job %d belongs to a different run %d, want %d", job.ID, job.RunID, runID)
			}
			if !strings.EqualFold(strings.TrimSpace(job.HeadSHA), headSHA) {
				return nil, fmt.Errorf("GitHub Actions job %d belongs to a different head %q, want %q", job.ID, job.HeadSHA, headSHA)
			}
			job.Name = strings.TrimSpace(job.Name)
			job.Status = strings.ToLower(strings.TrimSpace(job.Status))
			if job.Name == "" {
				return nil, fmt.Errorf("GitHub Actions job %d is without a name", job.ID)
			}
			if job.Status == "" {
				return nil, fmt.Errorf("GitHub Actions job %d is without a status", job.ID)
			}
			if raw := strings.TrimSpace(job.CompletedAtRaw); raw != "" {
				completedAt, err := time.Parse(time.RFC3339, raw)
				if err != nil {
					return nil, fmt.Errorf("GitHub Actions job %d has malformed completed_at: %w", job.ID, err)
				}
				job.completedAt = completedAt
			}
			jobs = append(jobs, job)
		}
	}
	if len(seen) != total {
		return nil, fmt.Errorf("GitHub Actions job discovery for run %d returned %d unique jobs, want %d", runID, len(seen), total)
	}
	return jobs, nil
}

func normalizeActionsState(status string, conclusion *string) (scm.CheckBucket, string) {
	normalizedStatus := strings.ToUpper(strings.TrimSpace(status))
	switch normalizedStatus {
	case "QUEUED", "IN_PROGRESS", "WAITING", "REQUESTED", "PENDING", "EXPECTED":
		// A nonterminal status remains pending even if a malformed or lagging
		// response also carries an old conclusion.
		return scm.CheckBucketPending, normalizedStatus
	case "COMPLETED":
		// Only a completed response may derive readiness from its conclusion.
	default:
		if normalizedStatus == "" {
			normalizedStatus = "UNKNOWN"
		}
		// Future statuses may have semantics that differ from today's API.
		// Ignore any accompanying conclusion until those semantics are known.
		return scm.CheckBucketPending, normalizedStatus
	}

	state := "COMPLETED"
	if conclusion != nil && strings.TrimSpace(*conclusion) != "" {
		state = strings.ToUpper(strings.TrimSpace(*conclusion))
	}
	switch state {
	case "SUCCESS":
		return scm.CheckBucketPass, state
	case "FAILURE", "ERROR", "TIMED_OUT", "ACTION_REQUIRED", "STARTUP_FAILURE":
		return scm.CheckBucketFail, state
	case "CANCELLED":
		return scm.CheckBucketCancel, state
	case "SKIPPED", "NEUTRAL", "STALE":
		return scm.CheckBucketSkip, state
	default:
		return scm.CheckBucketPending, state
	}
}

func actionsEventSupportsExactPRHead(event string) bool {
	switch strings.ToLower(strings.TrimSpace(event)) {
	case "push", "pull_request", "workflow_dispatch", "repository_dispatch", "workflow_call", "workflow_run", "schedule":
		return true
	default:
		return false
	}
}

func bucketRepresented(checks []scm.Check, bucket scm.CheckBucket) bool {
	for _, check := range checks {
		if check.Bucket == bucket {
			return true
		}
	}
	return false
}

func numericPRNumber(pr *scm.PR) (string, error) {
	if pr == nil {
		return "", errors.New("Actions-only GitHub observation requires a numeric PR")
	}
	number := strings.TrimSpace(pr.Number)
	if number == "" && strings.TrimSpace(pr.URL) != "" {
		var err error
		number, err = scm.ExtractPRNumber(pr.URL)
		if err != nil {
			return "", fmt.Errorf("Actions-only GitHub observation requires a numeric PR: %w", err)
		}
	}
	parsed, err := strconv.ParseInt(number, 10, 64)
	if err != nil || parsed <= 0 || strconv.FormatInt(parsed, 10) != number {
		return "", fmt.Errorf("Actions-only GitHub observation requires a numeric PR, got %q", number)
	}
	return number, nil
}

func (h *Host) actionsRepoSlug() (string, error) {
	repo := strings.Trim(strings.TrimSpace(h.repo), "/")
	if h.host != "" {
		prefix := strings.TrimSpace(h.host) + "/"
		if len(repo) > len(prefix) && strings.EqualFold(repo[:len(prefix)], prefix) {
			repo = repo[len(prefix):]
		}
	}
	parts := strings.Split(repo, "/")
	if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
		return "", fmt.Errorf("Actions-only GitHub observation requires an explicit base repository, got %q", h.repo)
	}
	return strings.TrimSpace(parts[0]) + "/" + strings.TrimSpace(parts[1]), nil
}

func validGitHubSHA(value string) bool {
	if len(value) != 40 && len(value) != 64 {
		return false
	}
	for _, r := range value {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			return false
		}
	}
	return true
}

func (h *Host) runGitHubAPI(ctx context.Context, endpoint string) ([]byte, error) {
	args := []string{"api"}
	if h.host != "" {
		args = append(args, "--hostname", h.host)
	}
	args = append(args, "--method", "GET", endpoint)
	out, err := h.cmd(ctx, "gh", args...).CombinedOutput()
	if err != nil {
		return nil, githubCommandError(ctx, "gh api "+endpoint, out, err)
	}
	return out, nil
}

func (h *Host) runGitHubAPIPaginated(ctx context.Context, endpoint string, filters ...string) ([]byte, error) {
	args := []string{"api"}
	if h.host != "" {
		args = append(args, "--hostname", h.host)
	}
	args = append(args, "--method", "GET", endpoint)
	for _, filter := range filters {
		args = append(args, "-f", filter)
	}
	args = append(args, "-f", "per_page=100", "--paginate", "--slurp")
	out, err := h.cmd(ctx, "gh", args...).CombinedOutput()
	if err != nil {
		return nil, githubCommandError(ctx, "gh api "+endpoint, out, err)
	}
	return out, nil
}

func (h *Host) actionsRunURL(repo string, runID int64) string {
	host := strings.TrimSpace(h.host)
	if host == "" {
		host = "github.com"
	}
	return fmt.Sprintf("https://%s/%s/actions/runs/%d", host, repo, runID)
}

func (h *Host) actionsJobURL(repo string, runID, jobID int64) string {
	return fmt.Sprintf("%s/job/%d", h.actionsRunURL(repo, runID), jobID)
}

func githubCommandError(ctx context.Context, operation string, output []byte, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	if detail := boundedGitHubCommandOutput(output); detail != "" {
		return fmt.Errorf("%s: %s: %w", operation, detail, err)
	}
	return fmt.Errorf("%s: %w", operation, err)
}

func boundedGitHubCommandOutput(output []byte) string {
	text := strings.TrimSpace(safeurl.RedactText(string(output)))
	if len(text) <= maxGitHubCommandOutput {
		return text
	}
	cut := maxGitHubCommandOutput
	for cut > 0 && !utf8.RuneStart(text[cut]) {
		cut--
	}
	return text[:cut] + "...[truncated]"
}
