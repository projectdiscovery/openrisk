package openrisk

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/projectdiscovery/gologger"
)

type IssueProcessor struct {
	path    string
	parsers map[string]IssueParser
}

func NewIssueProcessor(path string) *IssueProcessor {
	return &IssueProcessor{path: path, parsers: map[string]IssueParser{
		".md":    NewMarkdownIssueParser(),
		".jsonl": NewJsonlIssueParser(),
		".txt":   NewTxtIssueParser(),
	}}
}

func (ip *IssueProcessor) Process() (string, error) {
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

func (ip *IssueProcessor) processFile(path string) (string, error) {
	nucleiScanResult, err := os.ReadFile(path)
	if err != nil {
		gologger.Error().Msgf("Could not read the nuclei scan result: %v", err)
		return "", err
	}

	ext := filepath.Ext(path)
	parser, ok := ip.parsers[ext]
	if !ok {
		gologger.Error().Msgf("Unknown file type: %v", path)
		return "", errors.New("unknown file type")
	}

	return parser.Parse(nucleiScanResult)
}
