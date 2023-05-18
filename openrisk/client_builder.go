package openrisk

import gogpt "github.com/sashabaranov/go-gpt3"

type ClientBuilder struct {
	openAiApiKey string
}

func newClientBuilder() *ClientBuilder {
	return &ClientBuilder{}
}

func (b *ClientBuilder) apiKey(apiKey string) *ClientBuilder {
	b.openAiApiKey = apiKey
	return b
}

func (b *ClientBuilder) build() gogpt.Client {
	client := gogpt.NewClient(b.openAiApiKey)
	return *client
}
