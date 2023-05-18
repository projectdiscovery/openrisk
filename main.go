package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/openrisk/openrisk"
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

	files, isValidPath := getFiles(*input)
	if !isValidPath {
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

// getFiles: returns a list of files in the given directory or the file itself
func getFiles(input string) ([]string, bool) {
	var files []string

	filedetails, err := os.Stat(input)
	if err != nil {
		gologger.Error().Msgf("Invalid filename or directory: %v", err)
		return nil, false
	}

	if filedetails.IsDir() {
		dir, err := os.Open(input)
		if err != nil {
			gologger.Error().Msgf("Could not read the directory: %v", err)
			return nil, false
		}
		fileInfos, _ := dir.Readdir(-1)
		for _, fileInfo := range fileInfos {
			files = append(files, input+"/"+fileInfo.Name())
		}
		defer dir.Close()

	} else {
		files = append(files, input)
	}
	return files, true
}

// getApiKey: returns the API key from the OPENAI_API_KEY environment variable
func getApiKey() string {
	var apiKey = os.Getenv("OPENAI_API_KEY")
	if apiKey == "" {
		gologger.Error().Msg("Environment variable OPENAI_API_KEY is not set.")
		os.Exit(1)
	}
	return apiKey
}
