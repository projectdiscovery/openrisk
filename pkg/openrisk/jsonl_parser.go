package openrisk

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

func ParseJsonL(nucleiScanResult []byte) (string, error) {
	// Initialize the empty results string. This will be in the format "template_name,severity\n" to match the resulting
	// string from the Markdown parsing in parseMD()
	results := ""

	var errs []error

	// Loop through the lines of the file and parse each row as a JSON object as Nuclei exports the json
	// file as a JSON-line file
	scanner := bufio.NewScanner(strings.NewReader(string(nucleiScanResult)))
	// Nuclei JSONL lines include the raw request and response, which can exceed the default 64 KiB token size.
	// The whole file is already in memory, so allow a single line to be as long as the file itself.
	scanner.Buffer(make([]byte, 0, bufio.MaxScanTokenSize), len(nucleiScanResult)+1)
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
			errs = append(errs, err)
			continue
		}
		results += fmt.Sprintf("%s,%s\n", result.Info.Name, result.Info.Severity)
	}
	if err := scanner.Err(); err != nil {
		errs = append(errs, err)
	}

	return results, errors.Join(errs...)
}
