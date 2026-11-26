package openrisk

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	gogpt "github.com/sashabaranov/go-openai"
)

func TestGetScoreWithIssuesRequest(t *testing.T) {
	var body map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decode request: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":" Risk Score: 5 "}}]}`))
	}))
	defer server.Close()

	config := gogpt.DefaultConfig("test")
	config.BaseURL = server.URL
	o := &OpenRisk{Options: &Options{ApiKey: "test"}, client: gogpt.NewClientWithConfig(config)}

	got, err := o.GetScoreWithIssues("[2023-01-01 00:00:00] [a] [http] [high] https://example.com\n")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Score != "Risk Score: 5" {
		t.Fatalf("got score %q", got.Score)
	}
	if body["model"] != "gpt-6-luna" {
		t.Fatalf("got model %v, want gpt-6-luna", body["model"])
	}
	// Reasoning models reject sampling and legacy token limit params.
	for _, field := range []string{"temperature", "top_p", "logprobs", "top_logprobs", "max_tokens"} {
		if _, ok := body[field]; ok {
			t.Errorf("request must not send %q", field)
		}
	}
}
