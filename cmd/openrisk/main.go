package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/openrisk/pkg/openrisk"
)

var version = "0.0.1"

var banner = fmt.Sprintf(`
                               _      __  
  ____  ____  ___  ____  _____(_)____/ /__
 / __ \/ __ \/ _ \/ __ \/ ___/ / ___/ //_/
/ /_/ / /_/ /  __/ / / / /  / (__  ) ,<   
\____/ .___/\___/_/ /_/_/  /_/____/_/|_|  Powered by OpenAI (GPT-3)
    /_/                                   v%s (experimental)                                          
  `, version)

func printBanner() {
	gologger.Print().Msgf("%s\n", banner)
	gologger.Print().Msgf("\t\tprojectdiscovery.io\n\n")
}

var input = flag.String("i", "", "Nuclei scan result file or directory path. Supported file extensions: .txt, .md, .jsonl")

func main() {
	printBanner()
	flag.Parse()

	if *input == "" {
		flag.PrintDefaults()
		return
	}

	apiKey := getApiKey()
	options := &openrisk.Options{ApiKey: apiKey}
	openRisk, _ := openrisk.New(options)

	issueProcessor := openrisk.NewIssueProcessor(*input)
	issues, err := issueProcessor.Process()
	if err != nil {
		flag.PrintDefaults()
		return
	}

	nucleiScan, _ := openRisk.GetScore(issues)
	gologger.Info().Label("RISK SCORE").Msg(nucleiScan.Score)
}

func getApiKey() string {
	var apiKey = os.Getenv("OPENAI_API_KEY")
	if apiKey == "" {
		gologger.Error().Msg("Environment variable OPENAI_API_KEY is not set.")
		os.Exit(1)
	}
	return apiKey
}
