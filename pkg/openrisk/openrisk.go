package openrisk

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/projectdiscovery/gologger"
	gogpt "github.com/sashabaranov/go-gpt3"
)

const Question = "Calculate the 10-scale risk score for the following Nuclei scan results. The format of the CSV is 'finding,severity'. Write an executive summary of vulnerabilities with 30 words max."

func New(options *Options) (*OpenRisk, error) {
	gptClient := newClientBuilder().
		apiKey(options.ApiKey).
		build()
	return &OpenRisk{client: gptClient}, nil

}

func (o *OpenRisk) GetScore(scanIssues string) (NucleiScan, error) {
	issues := reduceTokens(scanIssues)
	if len(issues) == 0 {
		return NucleiScan{Issues: scanIssues, Score: "Risk Score: 0 \nExecutive Summary: No vulnerabilities found."}, nil
	}

	prompt := buildPrompt(issues)
	req := buildRequest(prompt)
	resp := makeRequest(o.client, req)
	return NucleiScan{Issues: scanIssues, Score: strings.TrimSpace(resp.Choices[0].Text)}, nil
}

func parseMD(nucleiScanResult []byte) string {
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

	return results["details"] + "," + results["severity"] + "\n"
}

func parseJSONL(nucleiScanResult []byte) string {
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

	return results
}

func makeRequest(c gogpt.Client, req gogpt.CompletionRequest) gogpt.CompletionResponse {
	resp, err := c.CreateCompletion(context.Background(), req)
	if err != nil {
		gologger.Error().Msgf("An error occurred while getting the completion: %v", err)
		os.Exit(1)
	}
	return resp
}

func buildRequest(prompt string) gogpt.CompletionRequest {
	req := gogpt.CompletionRequest{
		Model:            "text-davinci-003",
		Temperature:      0.01, // FIXME: https://github.com/sashabaranov/go-gpt3/issues/9
		TopP:             1,
		FrequencyPenalty: 0.01,
		PresencePenalty:  0.01,
		BestOf:           1,
		MaxTokens:        256,
		Prompt:           prompt,
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
