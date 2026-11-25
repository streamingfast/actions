package github_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/streamingfast/actions/image-scan/internal/github"
)

// server answers by "METHOD path?query" and records the requests as "METHOD path?query body".
func server(t *testing.T, routes map[string]func(w http.ResponseWriter, body string)) (*github.Client, *[]string) {
	t.Helper()
	var requests []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, _ := io.ReadAll(r.Body)
		key := r.Method + " " + r.URL.RequestURI()
		requests = append(requests, key+" "+string(data))
		assert.Equal(t, "Bearer tok", r.Header.Get("Authorization"))
		route, ok := routes[key]
		if !ok {
			http.Error(w, "unexpected "+key, http.StatusNotFound)
			return
		}
		route(w, string(data))
	}))
	t.Cleanup(srv.Close)
	return github.NewClient(srv.URL, "tok"), &requests
}

func TestComments(t *testing.T) {
	page := func(from, n int) string {
		comments := make([]github.Comment, n)
		for i := range comments {
			comments[i] = github.Comment{ID: int64(from + i), Body: "b"}
		}
		data, _ := json.Marshal(comments)
		return string(data)
	}
	c, requests := server(t, map[string]func(http.ResponseWriter, string){
		"GET /repos/o/r/issues/7/comments?per_page=100&page=1": func(w http.ResponseWriter, _ string) { fmt.Fprint(w, page(1, 100)) },
		"GET /repos/o/r/issues/7/comments?per_page=100&page=2": func(w http.ResponseWriter, _ string) { fmt.Fprint(w, page(101, 5)) },
		"POST /repos/o/r/issues/7/comments":                    func(w http.ResponseWriter, _ string) { w.WriteHeader(http.StatusCreated); fmt.Fprint(w, "{}") },
		"PATCH /repos/o/r/issues/comments/55":                  func(w http.ResponseWriter, _ string) { fmt.Fprint(w, "{}") },
	})

	comments, err := c.ListComments(t.Context(), "o/r", 7)
	require.NoError(t, err)
	assert.Len(t, comments, 105, "every page is read")

	require.NoError(t, c.CreateComment(t.Context(), "o/r", 7, "hello"))
	require.NoError(t, c.UpdateComment(t.Context(), "o/r", 55, "new"))
	assert.Contains(t, *requests, `POST /repos/o/r/issues/7/comments {"body":"hello"}`)
	assert.Contains(t, *requests, `PATCH /repos/o/r/issues/comments/55 {"body":"new"}`)
}

func TestListIssuesSkipsPullRequestsAndNormalisesState(t *testing.T) {
	c, _ := server(t, map[string]func(http.ResponseWriter, string){
		"GET /repos/o/r/issues?labels=image-scan-skipped&state=open&per_page=100&page=1": func(w http.ResponseWriter, _ string) {
			fmt.Fprint(w, `[{"number":1,"state":"open","body":"b","html_url":"u","labels":[{"name":"security"}]},{"number":2,"state":"open","pull_request":{}}]`)
		},
	})
	issues, err := c.ListIssues(t.Context(), "o/r", "image-scan-skipped", "open", 200)
	require.NoError(t, err)
	require.Len(t, issues, 1, "the pull requests the endpoint lists are dropped")
	assert.Equal(t, github.Issue{Number: 1, State: "OPEN", Body: "b", URL: "u", Labels: []string{"security"}}, issues[0])
	assert.True(t, issues[0].HasLabel("security"))
	assert.False(t, issues[0].HasLabel("risk-accepted"))
}

func TestIssueMutations(t *testing.T) {
	ok := func(w http.ResponseWriter, _ string) { fmt.Fprint(w, "{}") }
	c, requests := server(t, map[string]func(http.ResponseWriter, string){
		"POST /repos/o/r/issues":                          func(w http.ResponseWriter, _ string) { w.WriteHeader(201); fmt.Fprint(w, `{"html_url":"https://x/1"}`) },
		"PATCH /repos/o/r/issues/3":                       ok,
		"POST /repos/o/r/issues/3/labels":                 ok,
		"DELETE /repos/o/r/issues/3/labels/severity:high": ok,
		"POST /repos/o/r/issues/3/comments":               ok,
		"POST /repos/o/r/labels":                          ok,
	})

	url, err := c.CreateIssue(t.Context(), "o/r", "t", "b", []string{"security"})
	require.NoError(t, err)
	assert.Equal(t, "https://x/1", url)

	require.NoError(t, c.EditIssue(t.Context(), "o/r", 3, "t", "b"))
	require.NoError(t, c.AddLabel(t.Context(), "o/r", 3, "severity:critical"))
	require.NoError(t, c.RemoveLabel(t.Context(), "o/r", 3, "severity:high"))
	require.NoError(t, c.CloseIssue(t.Context(), "o/r", 3, "done"))
	require.NoError(t, c.CreateLabel(t.Context(), "o/r", "security", "B60205"))

	assert.Contains(t, strings.Join(*requests, "\n"), `POST /repos/o/r/issues/3/comments {"body":"done"}`, "closing comments first")
	assert.Contains(t, strings.Join(*requests, "\n"), `PATCH /repos/o/r/issues/3 {"state":"closed"}`)
}

func TestReleases(t *testing.T) {
	c, _ := server(t, map[string]func(http.ResponseWriter, string){
		"GET /repos/o/r/releases/latest":       func(w http.ResponseWriter, _ string) { fmt.Fprint(w, `{"tag_name":"v1.2.3"}`) },
		"GET /repos/o/r/releases/tags/v1.2.3":  func(w http.ResponseWriter, _ string) { fmt.Fprint(w, `{"published_at":"2026-01-02T03:04:05Z"}`) },
		"GET /repos/o/r/releases/tags/no-date": func(w http.ResponseWriter, _ string) { fmt.Fprint(w, `{}`) },
	})
	tag, err := c.LatestReleaseTag(t.Context(), "o/r")
	require.NoError(t, err)
	assert.Equal(t, "v1.2.3", tag)

	date, err := c.ReleasePublishedAt(t.Context(), "o/r", "v1.2.3")
	require.NoError(t, err)
	assert.Equal(t, "2026-01-02", date)

	_, err = c.ReleasePublishedAt(t.Context(), "o/r", "no-date")
	assert.Error(t, err)
}

func TestErrors(t *testing.T) {
	c, _ := server(t, nil)
	_, err := c.LatestReleaseTag(t.Context(), "o/r")
	apiErr, ok := err.(*github.Error)
	require.True(t, ok)
	assert.Equal(t, http.StatusNotFound, apiErr.Status)
}
