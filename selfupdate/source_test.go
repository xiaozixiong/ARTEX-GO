package selfupdate

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

type sourceTransport func(*http.Request) (*http.Response, error)

func (f sourceTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestFetchLatestUsesForkAndFailsClosedWithoutRelease(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusNotFound} {
		requests := 0
		client := &http.Client{Transport: sourceTransport(func(r *http.Request) (*http.Response, error) {
			requests++
			if r.URL.String() != "https://api.github.com/repos/xiaozixiong/ARTEX-GO/releases/latest" {
				t.Fatalf("unexpected release source: %s", r.URL)
			}
			return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(`{"tag_name":"v1.0.0"}`)), Header: make(http.Header)}, nil
		})}
		rel, err := FetchLatest(context.Background(), client)
		if status == http.StatusOK && (err != nil || rel.TagName != "v1.0.0") {
			t.Fatalf("valid fork release failed: %v", err)
		}
		if status == http.StatusNotFound && (rel != nil || err == nil || !strings.Contains(err.Error(), Repo)) {
			t.Fatalf("missing release must fail for this repository: %v", err)
		}
		if requests != 1 {
			t.Fatalf("unexpected fallback request count: %d", requests)
		}
	}
}
