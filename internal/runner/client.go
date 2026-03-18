package runner

import (
	"context"
	"fmt"

	openai "github.com/sashabaranov/go-openai"
)

// ChatClient wraps go-openai to talk to any OpenAI-compatible endpoint.
type ChatClient struct {
	client *openai.Client
	model  string
}

// NewChatClient creates a client pointed at the given endpoint.
// endpoint may be empty for the default OpenAI URL.
func NewChatClient(endpoint, apiKey, model string) *ChatClient {
	cfg := openai.DefaultConfig(apiKey)
	if endpoint != "" {
		cfg.BaseURL = endpoint
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
