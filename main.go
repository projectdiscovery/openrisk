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

var banner = fmt.Sprintf(`
experimental  
____  ____  ___  ____  _____(_)____/ /__
/ __ \/ __ \/ _ \/ __ \/ ___/ / ___/ //_/
/ /_/ / /_/ /  __/ / / / /  / (__  ) ,<   
\____/ .___/\___/_/ /_/_/  /_/____/_/|_|  Powered by OpenAI (GPT-3)
  /_/                                   
  `)

func printBanner() {
	gologger.Print().Msgf("%s\n", banner)
	gologger.Print().Msgf("\t\tprojectdiscovery.io\n\n")
}

const Question = "Calculate the 10-scale risk score for the following Nuclei scan results. The format of the CSV is 'finding,protocol,severity'"

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

	issues := readFiles(files)
	issues = reduceTokens(issues)
	var prompt = buildPrompt(issues)
	var completion = getCompletion(prompt)
	gologger.Info().Label("RISK SCORE").Msg(completion)
}

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
			gologger.Error().Msgf("Unknown file type (txt or md only): ", file)
		}
	}
	return issues
}

func getCompletion(prompt string) string {
	apiKey := getApiKey()
	c := newClientBuilder().
		apiKey(apiKey).
		build()

	req := buildRequest(prompt)
	resp := makeRequest(c, req)
	return strings.TrimSpace(resp.Choices[0].Text)
}

func makeRequest(c gogpt.Client, req gogpt.CompletionRequest) gogpt.CompletionResponse {
	resp, err := c.CreateCompletion(context.Background(), req)
	if err != nil {
		gologger.Error().Msgf("An error occurred while getting the completion.", err)
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

func getApiKey() string {
	var apiKey = os.Getenv("OPENAI_API_KEY")
	if apiKey == "" {
		gologger.Error().Msgf("Envirment variable OPENAI_API_KEY is not set.")
		os.Exit(1)
	}
	return apiKey
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
	scanner := bufio.NewScanner(strings.NewReader(issues))
	for scanner.Scan() {
		line := scanner.Text()
		line = dateRegex.ReplaceAllString(line, "")
		line = urlRegex.ReplaceAllString(line, "")
		// Make it CSV
		line = csvRegex.ReplaceAllString(line, ",")
		line = strings.Trim(line, "[],")
		sb.WriteString(line)
		sb.WriteString("\n")
	}
	return sb.String()
}

func parseMD(nucleiScanResult []byte) string {
	rName := regexp.MustCompile(`^\| Name \|\s*(.*)\s*\|$`)
	rSev := regexp.MustCompile(`^\| Severity \|\s*(.*)\s*\|$`)
	results := make(map[string]string)
	results["details"] = "??"
	results["severity"] = "unknown"

	scanner := bufio.NewScanner(strings.NewReader(string(nucleiScanResult)))
	for scanner.Scan() {
		line := scanner.Text()

		// If the line starts with "**", it is an easy key-value pair
		if strings.HasPrefix(line, "**") {
			pair := strings.Split(line, ":")
			if len(pair) < 2 {
				continue
			}
			results[pair[0]] = strings.TrimSpace(strings.Join(pair[1:], ":"))
		}

		// Otherwise get the specific values from the table
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
	}
	return (results["details"] + "," + results["**Protocol**"] + "," + results["severity"] + "\n")
}
