package main

import (
	"fmt"
	"log"
	"os"

	"github.com/projectdiscovery/openrisk/pkg/openrisk"
)

func main() {
	apiKey := os.Getenv("OPENAI_API_KEY")
	options := &openrisk.Options{ApiKey: apiKey}
	openRisk, err := openrisk.New(options)
	if err != nil {
		log.Fatal(err)
	}

	file := "example_nuclei_scan.txt"
	issues, err := openRisk.ParseIssuesWithFile(file)
	if err != nil {
		log.Fatal(err)
	}

	nucleiScan, err := openRisk.GetScoreWithIssues(issues)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(nucleiScan.Score)
}
