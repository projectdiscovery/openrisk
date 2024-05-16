package main

import (
	"errors"
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
\____/ .___/\___/_/ /_/_/  /_/____/_/|_|  Powered by OpenAI (GPT-4o)
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
	flagSet.SetDescription(`openrisk is an experimental tool generates a risk score from nuclei output for the host using OpenAI's GPT-4o model.`)
	flagSet.CreateGroup("input", "Input",
		flagSet.StringSliceVarP(&cliOptions.Files, "files", "f", nil, "Nuclei scan result file or directory path. Supported file extensions: .txt, .md, .jsonl", goflags.CommaSeparatedStringSliceOptions),
	)

	if err := flagSet.Parse(); err != nil {
		gologger.Error().Msg("could not parse flags")
		return
	}

	if len(cliOptions.Files) == 0 {
		gologger.Fatal().Msgf("no input provided")
	}

	apiKey, err := getApiKey()
	if err != nil {
		gologger.Fatal().Msgf("%s\n", err)
	}
	options := &openrisk.Options{ApiKey: apiKey}
	openRisk, _ := openrisk.New(options)

	for _, file := range cliOptions.Files {
		issues, err := openRisk.ParseIssuesWithFile(file)
		if err != nil {
			gologger.Error().Msgf("Could not parse issues: %v", err)
		}

		nucleiScan, _ := openRisk.GetScoreWithIssues(issues)
		gologger.Info().Label("RISK SCORE[" + file + "]").Msg(nucleiScan.Score)
	}
}

func getApiKey() (string, error) {
	apiKey := os.Getenv("OPENAI_API_KEY")
	if apiKey == "" {
		return "", errors.New("Environment variable for OPENAI_API_KEY is not set.")
	}
	return apiKey, nil
}
