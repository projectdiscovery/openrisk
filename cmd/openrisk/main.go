package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/projectdiscovery/goflags"
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

type CliOptions struct {
	Files goflags.StringSlice
}

var cliOptions = CliOptions{}

func main() {
	printBanner()
	flagSet := goflags.NewFlagSet()
	flagSet.StringSliceVarP(&cliOptions.Files, "files", "f", nil, "scan result file/files", goflags.CommaSeparatedStringSliceOptions)

	if err := flagSet.Parse(); err != nil {
		gologger.Error().Msg("could not parse flags")
		return
	}

	if len(cliOptions.Files) == 0 {
		flagSet.CommandLine.PrintDefaults()
		return
	}

	apiKey := getApiKey()
	options := &openrisk.Options{ApiKey: apiKey}
	openRisk, _ := openrisk.New(options)

	for _, file := range cliOptions.Files {
		issueProcessor := openrisk.NewIssueProcessor(file)
		issues, err := issueProcessor.Process()
		if err != nil {
			flag.PrintDefaults()
			return
		}

		nucleiScan, _ := openRisk.GetScore(issues)
		gologger.Info().Label("RISK SCORE[" + file + "]").Msg(nucleiScan.Score)
	}
}

func getApiKey() string {
	var apiKey = os.Getenv("OPENAI_API_KEY")
	if apiKey == "" {
		gologger.Error().Msg("Environment variable OPENAI_API_KEY is not set.")
		os.Exit(1)
	}
	return apiKey
}
