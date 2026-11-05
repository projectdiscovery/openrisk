package openrisk

import (
	"strings"
	"testing"
)

func TestParseJsonL(t *testing.T) {
	input := `{"template-id":"a","info":{"name":"First finding","severity":"high"}}
{"template-id":"b","info":{"name":"Second finding","severity":"low"}}
`
	got, err := ParseJsonL([]byte(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "First finding,high\nSecond finding,low\n"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestParseJsonLLongLine(t *testing.T) {
	// Nuclei JSONL lines include the raw request and response, which can be
	// larger than the default bufio.Scanner token size of 64 KiB.
	response := strings.Repeat("A", 128*1024)
	input := `{"template-id":"a","info":{"name":"Large response","severity":"critical"},"response":"` + response + `"}
{"template-id":"b","info":{"name":"After large response","severity":"medium"}}
`
	got, err := ParseJsonL([]byte(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "Large response,critical\nAfter large response,medium\n"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}
