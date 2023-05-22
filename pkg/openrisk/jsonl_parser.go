package openrisk

import (
	"bufio"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/projectdiscovery/gologger"
)

type JsonlIssueParser struct {
}

func NewJsonlIssueParser() *JsonlIssueParser {
	return &JsonlIssueParser{}
}

func (jip *JsonlIssueParser) Parse(nucleiScanResult []byte) (string, error) {
	// Initialize the empty results string. This will be in the format "template_name,severity\n" to match the resulting
	// string from the Markdown parsing in parseMD()
	results := ""

	// Loop through the lines of the file and parse each row as a JSON object as Nuclei exports the json
	// file as a JSON-line file
	scanner := bufio.NewScanner(strings.NewReader(string(nucleiScanResult)))
	for scanner.Scan() {
		line := scanner.Text()
		// Set the default and minimally required fields for the NucleiResult struct that are utilized in the result
		// parsing below
		result := NucleiResult{
			Info: NucleiInfo{
				Name:     "",
				Severity: "",
			},
		}
		//var result NucleiResult
		err := json.Unmarshal([]byte(line), &result)
		if err != nil {
			// Don't fatally break on a corrupt JSON object
			gologger.Error().Msgf("failed to parse nuclei JSONL got %v", err)
			continue
		}
		results += fmt.Sprintf("%s,%s\n", result.Info.Name, result.Info.Severity)
	}

	return results, nil
}
