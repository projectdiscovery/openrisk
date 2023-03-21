package main

type NucleiResultClassification struct {
	CveID string   `json:"cve-id"`
	CweID []string `json:"cwe-id"`
}

type NucleiResultInfo struct {
	Name           string
	Author         []string
	Tags           []string
	Description    string
	Reference      []string
	Severity       string
	Classification NucleiResultClassification
}

type NucleiResult struct {
	Template      string
	TemplateUrl   string `json:"template-url"`
	TemplateID    string `json:"template-id"`
	TemplatePath  string `json:"template-path"`
	Info          NucleiResultInfo
	MatcherName   string `json:"matcher-name"`
	Type          string
	Host          string
	Ip            string
	Timestamp     string
	CurlCommand   string `json:"curl-command"`
	MatcherStatus bool   `json:"matcher-status"`
	MatchedLine   string `json:"matched-line"`
}
