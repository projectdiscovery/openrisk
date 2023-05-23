package openrisk

import gogpt "github.com/sashabaranov/go-gpt3"

type OpenRisk struct {
	Options *Options
	client  *gogpt.Client
}

type Options struct {
	ApiKey string
}

type NucleiScan struct {
	Issues string
	Score  string
}

// The JSON types do not define the entire structure of the JSON object that is exported by Nuclei, but rather only
// the fields that are used in the issue list generation. This reduces the amount of data that is parsed from the JSON
// file as well as reducing the risk of a change in the Nuclei JSON export format breaking the issue list generation.

type NucleiInfo struct {
	Name     string `json:"name,omitempty"`
	Severity string `json:"severity,omitempty"`
}

type NucleiResult struct {
	Info NucleiInfo
}
