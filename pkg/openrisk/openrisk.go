package openrisk

import (
	"bufio"
	"context"
	"errors"
	"regexp"
	"strings"

	gogpt "github.com/sashabaranov/go-openai"
)

const Question = "Calculate the 10-scale risk score for the following Nuclei scan results. The format of the CSV is 'finding,severity'. Write an executive summary of vulnerabilities with 30 words max."

func New(options *Options) (*OpenRisk, error) {
	if options.ApiKey == "" {
		return nil, errors.New("api key not defined")
	}
	gptClient := gogpt.NewClient(options.ApiKey)
	openRisk := &OpenRisk{
		Options: options,
		client:  gptClient,
	}
	return openRisk, nil

}

func (o *OpenRisk) GetScoreWithIssues(scanIssues string) (NucleiScan, error) {
	issues := reduceTokens(scanIssues)
	if len(issues) == 0 {
		return NucleiScan{Issues: scanIssues, Score: "Risk Score: 0 \nExecutive Summary: No vulnerabilities found."}, nil
	}

	prompt := buildPrompt(issues)
	req := buildRequest(prompt)
	resp, err := o.makeRequest(req)
	if err != nil {
		return NucleiScan{}, err
	}
	if len(resp.Choices) == 0 {
		return NucleiScan{}, errors.New("no choices returned")
	}
	return NucleiScan{Issues: scanIssues, Score: strings.TrimSpace(resp.Choices[0].Message.Content)}, nil
}

func (o *OpenRisk) makeRequest(req gogpt.ChatCompletionRequest) (gogpt.ChatCompletionResponse, error) {
	return o.client.CreateChatCompletion(context.Background(), req)
}

func buildRequest(prompt string) gogpt.ChatCompletionRequest {
	req := gogpt.ChatCompletionRequest{
		Model:            "gpt-4o",
		Messages:         []gogpt.ChatCompletionMessage{{Role: "system", Content: "You're a security analyst reviewing a host's vulnerabilities."},
		 {Role: "user", Content: prompt}},
	}
	return req
}

func buildPrompt(nucleiScanResult string) string {
	var sb strings.Builder
	sb.WriteString(Question)
	sb.WriteString("\n")
	sb.WriteString(nucleiScanResult)
	return sb.String()
}

func reduceTokens(issues string) string {
	var sb strings.Builder
	dateRegex := regexp.MustCompile(`^\[\d{4}\-\d{2}\-\d{2} \d{2}:\d{2}:\d{2}\] `)
	urlRegex := regexp.MustCompile(`(https?:\/\/)?(www\.)?[-a-zA-Z0-9@:%._\+~#=]{2,256}\.[a-z]{2,6}\b([-a-zA-Z0-9@:%_\+.~#()?&//=]*)`)
	csvRegex := regexp.MustCompile(`\] \[?`)
	skipTxtRegex := regexp.MustCompile(`^(\[INF]|\[WRN]|\[ERR]|\[DBG]|\[FTL]|\s|\/|\\|\d)`)
	txtLine := regexp.MustCompile("^.*,.*,")
	scanner := bufio.NewScanner(strings.NewReader(issues))
	for scanner.Scan() {
		line := scanner.Text()

		// Skip lines that start with space, \, or [ but not [YYYY-MM-DD HH:MM:SS] (txt)
		if skipTxtRegex.MatchString(line) {
			continue
		}

		// Remove the date and URL
		line = dateRegex.ReplaceAllString(line, "")
		line = urlRegex.ReplaceAllString(line, "")

		// Make it CSV
		line = csvRegex.ReplaceAllString(line, ",")
		line = strings.Trim(line, "[],")

		// Remove the protocol (txt)
		if txtLine.MatchString(line) {
			parts := strings.Split(line, ",")
			line = parts[0] + "," + parts[2]

		}

		// Skip info/unknown lines as they don't impact the score (md)
		if strings.HasSuffix(line, "info") || strings.HasSuffix(line, "unknown") {
			continue
		}

		// Skip lines that don't have 2 commas as it's not a valid vulnerability
		if strings.Count(line, ",") < 1 {
			continue
		}
		sb.WriteString(line + "\n")
	}
	return sb.String()
}
