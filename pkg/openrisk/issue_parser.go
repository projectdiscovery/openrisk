package openrisk

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/projectdiscovery/gologger"
)

type IssueParser struct {
	path string
}

func NewIssueParser(path string) *IssueParser {
	return &IssueParser{path: path}
}

func (ip *IssueParser) Parse() (string, error) {
	var issues strings.Builder

	err := filepath.Walk(ip.path, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			gologger.Error().Msgf("Invalid filename or directory: %v", err)
			return err
		}
		if !info.IsDir() {
			issue, err := ip.processFile(path)
			if err != nil {
				return err
			}
			issues.WriteString(issue)
		}
		return nil
	})
	return issues.String(), err
}

func (ip *IssueParser) processFile(path string) (string, error) {
	nucleiScanResult, err := os.ReadFile(path)
	if err != nil {
		gologger.Error().Msgf("Could not read the nuclei scan result: %v", err)
		return "", err
	}

	ext := filepath.Ext(path)
	switch ext {
	case ".md":
		return parseMD(nucleiScanResult), nil
	case ".jsonl":
		return parseJSONL(nucleiScanResult), nil
	case ".txt":
		return string(nucleiScanResult), nil
	default:
		gologger.Error().Msgf("Unknown file type: %v", path)
		return "", errors.New("unknown file type")
	}
}
