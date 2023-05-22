package openrisk

import (
	"bufio"
	"regexp"
	"strings"
)

type MarkdownIssueParser struct {
}

func NewMarkdownIssueParser() *MarkdownIssueParser {
	return &MarkdownIssueParser{}
}

func (mip *MarkdownIssueParser) Parse(nucleiScanResult []byte) (string, error) {
	rName := regexp.MustCompile(`^\| Name \|\s*(.*)\s*\|$`)
	rSev := regexp.MustCompile(`^\| Severity \|\s*(.*)\s*\|$`)
	results := make(map[string]string)
	results["details"] = ""
	results["severity"] = "unknown"

	scanner := bufio.NewScanner(strings.NewReader(string(nucleiScanResult)))
	for scanner.Scan() {
		line := scanner.Text()
		mName := rName.FindStringSubmatch(line)
		if len(mName) > 0 {
			results["details"] = strings.TrimSpace(mName[1])
			continue
		}

		mSev := rSev.FindStringSubmatch(line)
		if len(mSev) > 0 {
			results["severity"] = strings.TrimSpace(mSev[1])
			continue
		}

		if mSev != nil && mName != nil {
			break
		}
	}

	return results["details"] + "," + results["severity"] + "\n", nil
}
