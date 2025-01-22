package main

import (
	"fmt"

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
\____/ .___/\___/_/ /_/_/  /_/____/_/|_|
    /_/                                   v%s (experimental)                                          
  `, version)

func printBanner() {
	gologger.Print().Msgf("%s\n", banner)
	gologger.Print().Msgf("\t\tprojectdiscovery.io\n\n")
}

type CliOptions struct {
	ScanFile string
	Config   string
}

var cliOptions = CliOptions{}

func main() {
	printBanner()
	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription(`openrisk is an experimental tool generates a risk score from nuclei output for the asset.`)
	flagSet.CreateGroup("input", "Input",
		flagSet.StringVarP(&cliOptions.ScanFile, "scan-file", "sf", "", "Nuclei scan result file (JSON only, required)"),
		flagSet.StringVarP(&cliOptions.Config, "config", "c", "", "the filename of the config (required)"),
	)

	if err := flagSet.Parse(); err != nil {
		gologger.Error().Msg("could not parse flags")
		return
	}

	if cliOptions.ScanFile == "" {
		gologger.Fatal().Msgf("no input provided")
	}

	if cliOptions.Config == "" {
		gologger.Fatal().Msgf("no config provided")
	}

	options := &openrisk.Options{ConfigFile: cliOptions.Config}
	openRisk, err := openrisk.New(options)
	if err != nil {
		gologger.Fatal().Msgf("could not create openrisk: %v", err)
	}
	signals, err := openrisk.ParseSignals(cliOptions.ScanFile)
	if err != nil {
		gologger.Error().Msgf("Could not parse signals: %v", err)
	}

	gologger.Info().Label("RISK SCORE").Msgf("%.10f", openRisk.Scorer.ScoreRaw(signals))
}
