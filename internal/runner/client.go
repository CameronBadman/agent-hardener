package runner

import (
	"context"
	"fmt"
	"net/http"

	openai "github.com/sashabaranov/go-openai"
)

// ChatClient wraps go-openai to talk to any OpenAI-compatible endpoint.
type ChatClient struct {
	client *openai.Client
	model  string
}

// NewChatClient creates a client pointed at the given endpoint.
// extraHeaders are injected into every request — used for GitLab AI Gateway
// headers (e.g. x-gitlab-*) and Anthropic-specific headers.
func NewChatClient(endpoint, apiKey, model string, extraHeaders map[string]string) *ChatClient {
	cfg := openai.DefaultConfig(apiKey)
	if endpoint != "" {
		cfg.BaseURL = endpoint
	}
	if len(extraHeaders) > 0 {
		cfg.HTTPClient = &http.Client{
			Transport: &headerTransport{
				base:    http.DefaultTransport,
				headers: extraHeaders,
			},
		}
	}
	return &ChatClient{
		client: openai.NewClientWithConfig(cfg),
		model:  model,
	}
}

// Chat sends a single user message with the given system prompt and returns the response text.
func (c *ChatClient) Chat(ctx context.Context, systemPrompt, userMessage string) (string, error) {
	req := openai.ChatCompletionRequest{
		Model: c.model,
		Messages: []openai.ChatCompletionMessage{
			{Role: openai.ChatMessageRoleSystem, Content: systemPrompt},
			{Role: openai.ChatMessageRoleUser, Content: userMessage},
		},
	}

	resp, err := c.client.CreateChatCompletion(ctx, req)
	if err != nil {
		return "", fmt.Errorf("chat completion: %w", err)
	}
	if len(resp.Choices) == 0 {
		return "", fmt.Errorf("no choices in response")
	}
	return resp.Choices[0].Message.Content, nil
}

// headerTransport injects fixed headers into every outbound request.
type headerTransport struct {
	base    http.RoundTripper
	headers map[string]string
}

func (t *headerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Clone the request to avoid mutating the original
	r := req.Clone(req.Context())
	for k, v := range t.headers {
		r.Header.Set(k, v)
	}
	return t.base.RoundTrip(r)
}
