package main

import (
	"context"
	"flag"
	"fmt"
	"os"
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

const Question = "Calculate the 10-scale risk score for the following Nuclei scan result"

var input = flag.String("i", "", "Nuclei scan result file path")

func main() {
	printBanner()
	flag.Parse()

	if *input == "" {
		flag.PrintDefaults()
		return
	}

	bNucleiScanResult, err := os.ReadFile(*input)
	if err != nil {
		gologger.Error().Msgf("Could not read the nuclei scan result.", err)
		return
	}
	nucleiScanResult := string(bNucleiScanResult)
	var prompt = buildPrompt(nucleiScanResult)
	var completion = getCompletion(prompt)
	gologger.Info().Label("RISK SCORE").Msg(completion)
}

func getCompletion(prompt string) string {
	var apiKey = os.Getenv("OPENAI_API_KEY")
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
