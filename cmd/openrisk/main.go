package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

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

	files, err := getFiles(*input)
	if err != nil {
		flag.PrintDefaults()
		return
	}

	apiKey := getApiKey()
	options := &openrisk.Options{ApiKey: apiKey}
	openRisk, _ := openrisk.New(options)

	issues, _ := openRisk.ParseFiles(files)
	nucleiScan, _ := openRisk.GetScore(issues)
	gologger.Info().Label("RISK SCORE").Msg(nucleiScan.Score)
}

func getFiles(input string) ([]string, error) {
	var files []string
	err := filepath.Walk(input, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			gologger.Error().Msgf("Invalid filename or directory: %v", err)
			return err
		}
		if !info.IsDir() {
			files = append(files, path)
		}
		return nil
	})
	return files, err
}

func getApiKey() string {
	var apiKey = os.Getenv("OPENAI_API_KEY")
	if apiKey == "" {
		gologger.Error().Msg("Environment variable OPENAI_API_KEY is not set.")
		os.Exit(1)
	}
	return apiKey
}
