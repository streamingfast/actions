// Package github is the small part of the GitHub REST API the actions use: pull request comments, issues, labels, releases.
package github

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Comment of an issue or pull request.
type Comment struct {
	ID   int64  `json:"id"`
	Body string `json:"body"`
}

// Issue as the actions read it. State is OPEN or CLOSED.
type Issue struct {
	Number int
	State  string
	Title  string
	Body   string
	Labels []string
	URL    string
}

// HasLabel tells whether the issue carries the label.
func (i Issue) HasLabel(name string) bool {
	for _, l := range i.Labels {
		if l == name {
			return true
		}
	}
	return false
}

// API is what the actions need from GitHub, an interface so the logic is tested without the network.
type API interface {
	ListComments(ctx context.Context, repo string, number int) ([]Comment, error)
	CreateComment(ctx context.Context, repo string, number int, body string) error
	UpdateComment(ctx context.Context, repo string, id int64, body string) error

	// ListIssues lists the issues (not the pull requests) with a label, newest first, at most limit of them. State is open, closed or all.
	ListIssues(ctx context.Context, repo, label, state string, limit int) ([]Issue, error)
	CreateIssue(ctx context.Context, repo, title, body string, labels []string) (url string, err error)
	EditIssue(ctx context.Context, repo string, number int, title, body string) error
	AddLabel(ctx context.Context, repo string, number int, label string) error
	RemoveLabel(ctx context.Context, repo string, number int, label string) error
	CloseIssue(ctx context.Context, repo string, number int, comment string) error
	CommentIssue(ctx context.Context, repo string, number int, body string) error
	CreateLabel(ctx context.Context, repo, name, color string) error

	// LatestReleaseTag is the tag of the latest release (not a draft nor a pre-release).
	LatestReleaseTag(ctx context.Context, repo string) (string, error)
	// ReleasePublishedAt is the publication date (YYYY-MM-DD) of the release of a tag.
	ReleasePublishedAt(ctx context.Context, repo, tag string) (string, error)
}

// Client is the REST implementation of API.
type Client struct {
	BaseURL string // https://api.github.com by default, GITHUB_API_URL on GitHub Enterprise
	Token   string
	HTTP    *http.Client
}

// NewClient creates a client; an empty baseURL is github.com.
func NewClient(baseURL, token string) *Client {
	if baseURL == "" {
		baseURL = "https://api.github.com"
	}
	return &Client{BaseURL: strings.TrimRight(baseURL, "/"), Token: token, HTTP: &http.Client{Timeout: 60 * time.Second}}
}

// Error is a response that is not a success.
type Error struct {
	Method, Path string
	Status       int
	Body         string
}

func (e *Error) Error() string {
	return fmt.Sprintf("%s %s: HTTP %d: %s", e.Method, e.Path, e.Status, strings.TrimSpace(e.Body))
}

func (c *Client) do(ctx context.Context, method, path string, body, out any) error {
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "streamingfast-image-scan")
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return &Error{Method: method, Path: path, Status: resp.StatusCode, Body: string(data)}
	}
	if out != nil && len(data) > 0 {
		return json.Unmarshal(data, out)
	}
	return nil
}

const perPage = 100

func (c *Client) ListComments(ctx context.Context, repo string, number int) ([]Comment, error) {
	var all []Comment
	for page := 1; ; page++ {
		var comments []Comment
		path := fmt.Sprintf("/repos/%s/issues/%d/comments?per_page=%d&page=%d", repo, number, perPage, page)
		if err := c.do(ctx, http.MethodGet, path, nil, &comments); err != nil {
			return nil, err
		}
		all = append(all, comments...)
		if len(comments) < perPage {
			return all, nil
		}
	}
}

func (c *Client) CreateComment(ctx context.Context, repo string, number int, body string) error {
	return c.do(ctx, http.MethodPost, fmt.Sprintf("/repos/%s/issues/%d/comments", repo, number), map[string]string{"body": body}, nil)
}

func (c *Client) UpdateComment(ctx context.Context, repo string, id int64, body string) error {
	return c.do(ctx, http.MethodPatch, fmt.Sprintf("/repos/%s/issues/comments/%d", repo, id), map[string]string{"body": body}, nil)
}

type apiIssue struct {
	Number      int             `json:"number"`
	State       string          `json:"state"`
	Title       string          `json:"title"`
	Body        string          `json:"body"`
	HTMLURL     string          `json:"html_url"`
	PullRequest json.RawMessage `json:"pull_request"`
	Labels      []struct {
		Name string `json:"name"`
	} `json:"labels"`
}

func (a apiIssue) issue() Issue {
	issue := Issue{Number: a.Number, State: strings.ToUpper(a.State), Title: a.Title, Body: a.Body, URL: a.HTMLURL}
	for _, l := range a.Labels {
		issue.Labels = append(issue.Labels, l.Name)
	}
	return issue
}

func (c *Client) ListIssues(ctx context.Context, repo, label, state string, limit int) ([]Issue, error) {
	var issues []Issue
	for page := 1; len(issues) < limit; page++ {
		var batch []apiIssue
		path := fmt.Sprintf("/repos/%s/issues?labels=%s&state=%s&per_page=%d&page=%d", repo, url.QueryEscape(label), state, perPage, page)
		if err := c.do(ctx, http.MethodGet, path, nil, &batch); err != nil {
			return nil, err
		}
		for _, a := range batch {
			// the issues endpoint lists the pull requests too
			if len(a.PullRequest) == 0 && len(issues) < limit {
				issues = append(issues, a.issue())
			}
		}
		if len(batch) < perPage {
			break
		}
	}
	return issues, nil
}

func (c *Client) CreateIssue(ctx context.Context, repo, title, body string, labels []string) (string, error) {
	var created apiIssue
	err := c.do(ctx, http.MethodPost, fmt.Sprintf("/repos/%s/issues", repo), map[string]any{"title": title, "body": body, "labels": labels}, &created)
	return created.HTMLURL, err
}

func (c *Client) EditIssue(ctx context.Context, repo string, number int, title, body string) error {
	return c.do(ctx, http.MethodPatch, fmt.Sprintf("/repos/%s/issues/%d", repo, number), map[string]string{"title": title, "body": body}, nil)
}

func (c *Client) AddLabel(ctx context.Context, repo string, number int, label string) error {
	return c.do(ctx, http.MethodPost, fmt.Sprintf("/repos/%s/issues/%d/labels", repo, number), map[string][]string{"labels": {label}}, nil)
}

func (c *Client) RemoveLabel(ctx context.Context, repo string, number int, label string) error {
	return c.do(ctx, http.MethodDelete, fmt.Sprintf("/repos/%s/issues/%d/labels/%s", repo, number, url.PathEscape(label)), nil, nil)
}

func (c *Client) CloseIssue(ctx context.Context, repo string, number int, comment string) error {
	if comment != "" {
		if err := c.CommentIssue(ctx, repo, number, comment); err != nil {
			return err
		}
	}
	return c.do(ctx, http.MethodPatch, fmt.Sprintf("/repos/%s/issues/%d", repo, number), map[string]string{"state": "closed"}, nil)
}

func (c *Client) CommentIssue(ctx context.Context, repo string, number int, body string) error {
	return c.CreateComment(ctx, repo, number, body)
}

func (c *Client) CreateLabel(ctx context.Context, repo, name, color string) error {
	return c.do(ctx, http.MethodPost, fmt.Sprintf("/repos/%s/labels", repo), map[string]string{"name": name, "color": color}, nil)
}

func (c *Client) LatestReleaseTag(ctx context.Context, repo string) (string, error) {
	var release struct {
		TagName string `json:"tag_name"`
	}
	if err := c.do(ctx, http.MethodGet, fmt.Sprintf("/repos/%s/releases/latest", repo), nil, &release); err != nil {
		return "", err
	}
	return release.TagName, nil
}

func (c *Client) ReleasePublishedAt(ctx context.Context, repo, tag string) (string, error) {
	var release struct {
		PublishedAt string `json:"published_at"`
	}
	if err := c.do(ctx, http.MethodGet, fmt.Sprintf("/repos/%s/releases/tags/%s", repo, url.PathEscape(tag)), nil, &release); err != nil {
		return "", err
	}
	if len(release.PublishedAt) < 10 {
		return "", fmt.Errorf("release %s has no publication date", tag)
	}
	return release.PublishedAt[:10], nil
}
