package openrisk

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/projectdiscovery/gologger"
)

func (o *OpenRisk) ParseIssuesWithFile(path string) (string, error) {
	var issues strings.Builder

	err := filepath.Walk(path, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			gologger.Error().Msgf("Invalid filename or directory: %v", err)
			return err
		}
		if !info.IsDir() {
			issue, err := processFile(path)
			if err != nil {
				return err
			}
			issues.WriteString(issue)
		}
		return nil
	})
	return issues.String(), err
}

func processFile(path string) (string, error) {
	nucleiScanResult, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("Could not read the nuclei scan result: %v", err)
	}

	ext := filepath.Ext(path)
	switch ext {
	case ".jsonl":
		return ParseJsonL(nucleiScanResult)
	case ".md":
		return ParseMarkdown(nucleiScanResult)
	case ".txt":
		return string(nucleiScanResult), nil
	default:
		return "", fmt.Errorf("Unknown file type: %v", path)
	}
}
