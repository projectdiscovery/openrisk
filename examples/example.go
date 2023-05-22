package main

import (
	"os"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/openrisk/pkg/openrisk"
)

func main() {
	apiKey := os.Getenv("OPENAI_API_KEY")
	options := &openrisk.Options{ApiKey: apiKey}
	openRisk, _ := openrisk.New(options)

	file := "example_nuclei_scan.txt"
	issueProcessor := openrisk.NewIssueProcessor(file)
	issues, _ := issueProcessor.Process()

	nucleiScan, _ := openRisk.GetScore(issues)
	gologger.Info().Msg(nucleiScan.Score)
}
