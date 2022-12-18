package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"regexp"
	"strings"
	"unicode/utf8"

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

const Question = "Calculate the 10-scale risk score for the following Nuclei scan results. Theformat of the CSV is 'finding,protocol,severity,url'"

var input = flag.String("i", "", "Nuclei scan result file path")

func main() {
	printBanner()
	flag.Parse()

	if *input == "" {
		flag.PrintDefaults()
		return
	}

	var files []string

	// Check if the file is a directory
	filedetails, _ := os.Stat(*input)
	if filedetails.IsDir() {
		dir, err := os.Open(*input)
		if err != nil {
			gologger.Error().Msgf("Could not read the directory.", err)
			return
		}
		fileInfos, _ := dir.Readdir(-1)
		for _, fileInfo := range fileInfos {
			files = append(files, *input+"/"+fileInfo.Name())
		}
		defer dir.Close()

	} else {
		files = append(files, *input)
	}

	var finalIssues string
	for _, file := range files {
		// fmt.Print("* ", file, "\n")
		nucleiScanResult, err := os.ReadFile(file)
		if err != nil {
			gologger.Error().Msgf("Could not read the nuclei scan result.", err)
			continue
		}
		// Check if the file is a markdown file
		if strings.HasSuffix(file, ".md") {
			finalIssues += parseMD(nucleiScanResult)
		} else if strings.HasSuffix(file, ".txt") {
			finalIssues += string(nucleiScanResult)
		} else {
			gologger.Error().Msgf("Unknown file type (txt or md only): ", file)
		}
	}

	finalIssues = reduceTokens(finalIssues)
	fmt.Print(finalIssues)
	var prompt = buildPrompt(finalIssues)
	var completion = getCompletion(prompt)
	gologger.Info().Label("RISK SCORE").Msg(completion)

}

func getCompletion(prompt string) string {
	var apiKey = os.Getenv("OPENAI_API_KEY")
	if apiKey == "" {
		gologger.Error().Msgf("Envirment variable OPENAI_API_KEY is not set.")
		os.Exit(1)
	}
	c := gogpt.NewClient(apiKey)
	ctx := context.Background()

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
	resp, err := c.CreateCompletion(ctx, req)
	if err != nil {
		gologger.Error().Msgf("An error occurred while getting the completion.", err)
		return ""
	}
	return strings.TrimSpace(resp.Choices[0].Text)
}

func buildPrompt(nucleiScanResult string) string {
	var sb strings.Builder
	sb.WriteString(Question)
	sb.WriteString("\n")
	sb.WriteString(nucleiScanResult)
	return sb.String()
}

func reduceTokens(input string) string {
	var sb strings.Builder
	findingRegex := regexp.MustCompile(`^\[\d{4}\-\d{2}\-\d{2} \d{2}:\d{2}:\d{2}\] `)
	csvRegex := regexp.MustCompile(`\] \[?`)
	scanner := bufio.NewScanner(strings.NewReader(input))
	for scanner.Scan() {
		line := scanner.Text()
		// Only keep findings lines that start with a date
		if findingRegex.MatchString(line) {
			// Remove the date
			line = findingRegex.ReplaceAllString(line, "")
			// Make it CSV
			line = csvRegex.ReplaceAllString(line, ",")
			// Leftover leading [
			line = trimFirstRune(line)
			sb.WriteString(line)
			sb.WriteString("\n")
		}
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
	return (results["details"] + "," + results["**Protocol**"] + "," + results["severity"] + "," + results["**Full URL**"] + "\n")
}

// trimFirstRune removes the first rune from a string.
// https://stackoverflow.com/questions/48798588/how-do-you-remove-the-first-character-of-a-string
func trimFirstRune(s string) string {
	_, i := utf8.DecodeRuneInString(s)
	return s[i:]
}
