package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/projectdiscovery/gologger"
	gogpt "github.com/sashabaranov/go-gpt3"
)

var version = "0.0.1"

var banner = fmt.Sprintf(`
____  ____  ___  ____  _____(_)____/ /__
/ __ \/ __ \/ _ \/ __ \/ ___/ / ___/ //_/
/ /_/ / /_/ /  __/ / / / /  / (__  ) ,<   
\____/ .___/\___/_/ /_/_/  /_/____/_/|_| Powered by OpenAI (GPT-3)
  /_/ PD Research Experiment v%s
  `, version)

func printBanner() {
	gologger.Print().Msgf("%s\n", banner)
	gologger.Print().Msgf("\t\tprojectdiscovery.io\n\n")
}

const Question = "Calculate the 10-scale risk score for the following Nuclei scan results. The format of the CSV is 'finding,severity'. Write an executive summary of vulnerabilities with 30 words max."

var input = flag.String("i", "", "Nuclei scan result file or directory path. Supported file extensions: .txt, .md")

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

	var issues = readFiles(files)
	issues = reduceTokens(issues)
	if len(issues) == 0 {
		gologger.Info().Label("RISK SCORE").Msg("Risk Score: 0 \nExecutive Summary: No vulnerabilities found.")
		return
	}

	var prompt = buildPrompt(issues)
	var completion = getCompletion(prompt)
	gologger.Info().Label("RISK SCORE").Msg(completion)
}

// getFiles: returns a list of files in the given directory or the file itself
func getFiles(input string) ([]string, bool) {
	var files []string

	filedetails, err := os.Stat(input)
	if err != nil {
		gologger.Error().Msgf("Invalid filename or directory.", err)
		return nil, false
	}

	if filedetails.IsDir() {
		dir, err := os.Open(input)
		if err != nil {
			gologger.Error().Msgf("Could not read the directory.", err)
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

// readFiles: reads the file(s) and returns the issues
func readFiles(files []string) string {
	var issues string
	for _, file := range files {
		nucleiScanResult, err := os.ReadFile(file)
		if err != nil {
			gologger.Error().Msgf("Could not read the nuclei scan result.", err)
			continue
		}

		if strings.HasSuffix(file, ".md") {
			issues += parseMD(nucleiScanResult)
		} else if strings.HasSuffix(file, ".txt") {
			issues += string(nucleiScanResult)
		} else {
			gologger.Error().Msgf("Unknown file type: ", file)
		}
	}
	return issues
}

// getCompletion: returns the details from OpenAI
func getCompletion(prompt string) string {
	apiKey := getApiKey()
	c := newClientBuilder().
		apiKey(apiKey).
		build()

	req := buildRequest(prompt)
	resp := makeRequest(c, req)
	return strings.TrimSpace(resp.Choices[0].Text)
}

// makeRequest: makes the request to OpenAI
func makeRequest(c gogpt.Client, req gogpt.CompletionRequest) gogpt.CompletionResponse {
	resp, err := c.CreateCompletion(context.Background(), req)
	if err != nil {
		gologger.Error().Msgf("An error occurred while getting the completion.", err)
		os.Exit(1)
	}
	return resp
}

// buildRequest: builds the structured request to OpenAI
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

// getApiKey: returns the API key from the OPENAI_API_KEY environment variable
func getApiKey() string {
	var apiKey = os.Getenv("OPENAI_API_KEY")
	if apiKey == "" {
		gologger.Error().Msgf("Envirment variable OPENAI_API_KEY is not set.")
		os.Exit(1)
	}
	return apiKey
}

// buildPrompt: builds the prompt for OpenAI
func buildPrompt(nucleiScanResult string) string {
	var sb strings.Builder
	sb.WriteString(Question)
	sb.WriteString("\n")
	sb.WriteString(nucleiScanResult)
	return sb.String()
}

// reduceTokens: reduces the number of tokens sent to OpenAI
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
		if strings.HasSuffix(line, "info") || strings.HasSuffix(line, "unkonwn") {
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

// parseMD: parses the nuclei scan result in markdown format
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

	return (results["details"] + "," + results["severity"] + "\n")
}
