package notify

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWebhook(t *testing.T) {
	var got map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer t" {
			t.Errorf("auth header %q", r.Header.Get("Authorization"))
		}
		_ = json.NewDecoder(r.Body).Decode(&got)
	}))
	defer srv.Close()
	if err := (Webhook{URL: srv.URL, Token: "t"}).Send(t.Context(), "hello"); err != nil {
		t.Fatal(err)
	}
	if got["text"] != "hello" {
		t.Errorf("%v", got)
	}
	if err := (Webhook{}).Send(t.Context(), "x"); err != nil {
		t.Error("empty url should be a no-op")
	}
}

func TestQuote(t *testing.T) {
	if got := quote(`a "b" \c`); got != `"a \"b\" \\c"` {
		t.Errorf("%s", got)
	}
}
