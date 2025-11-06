package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
)

const PluginName = "accuknox-logger"

// Plugin configuration
type AccuKnoxConfig struct {
	Enabled  bool   `json:"enabled"`
	ApiKey   string `json:"api_key"`   // JWT token for AccuKnox API
	UserInfo string `json:"user_info"` // User email/name
}

// AccuKnox API client
type AccuKnoxClient struct {
	baseURL    string
	apiKey     string
	userInfo   string
	httpClient *http.Client
}

var pluginConfig AccuKnoxConfig
var accuknoxClient *AccuKnoxClient
var promptCache = make(map[string]string) // requestID -> inputContent mapping

// Environment URL mapping
var envURLs = map[string]string{
	"localhost": "http://localhost:8081/llm-defence/application-query",
	"dev":       "https://cwpp.dev.accuknox.com/llm-defence/application-query",
	"stage":     "https://cwpp.stage.accuknox.com/llm-defence/application-query",
	"demo":      "https://cwpp.demo.accuknox.com/llm-defence/application-query",
	"prod":      "https://cwpp.prod.accuknox.com/llm-defence/application-query",
}

// Init is called when the plugin is loaded
func Init(config any) error {
	log.Println("[AccuKnox Plugin] Init called")

	// Parse configuration
	if config != nil {
		configBytes, err := json.Marshal(config)
		if err != nil {
			return fmt.Errorf("failed to marshal config: %w", err)
		}

		if err := json.Unmarshal(configBytes, &pluginConfig); err != nil {
			return fmt.Errorf("failed to unmarshal config: %w", err)
		}
	}

	// Set defaults
	if pluginConfig.Enabled {
		log.Printf("[AccuKnox Plugin] Initialized with user_info: %s", pluginConfig.UserInfo)

		// Initialize AccuKnox client if API key is provided
		if pluginConfig.ApiKey != "" && pluginConfig.ApiKey != "your-accuknox-api-key-here" {
			client, err := initAccuKnoxClient(pluginConfig.ApiKey, pluginConfig.UserInfo)
			if err != nil {
				log.Printf("[AccuKnox Plugin] WARNING: Failed to initialize AccuKnox client: %v", err)
				log.Println("[AccuKnox Plugin] Will continue without AccuKnox API integration")
			} else {
				accuknoxClient = client
				log.Printf("[AccuKnox Plugin] AccuKnox API client initialized: %s", client.baseURL)
			}
		} else {
			log.Println("[AccuKnox Plugin] No valid API key provided, running without AccuKnox API integration")
		}
	} else {
		log.Println("[AccuKnox Plugin] Plugin disabled in config")
	}

	return nil
}

// initAccuKnoxClient initializes the AccuKnox API client
func initAccuKnoxClient(apiKey, userInfo string) (*AccuKnoxClient, error) {
	// Decode JWT token to get environment
	baseURL, err := getBaseURLFromToken(apiKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode token: %w", err)
	}

	client := &AccuKnoxClient{
		baseURL:  baseURL,
		apiKey:   apiKey,
		userInfo: userInfo,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}

	return client, nil
}

// getBaseURLFromToken decodes JWT token and determines the base URL
func getBaseURLFromToken(token string) (string, error) {
	// Split JWT token (format: header.payload.signature)
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("invalid JWT token format")
	}

	// Decode payload (second part)
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("failed to decode JWT payload: %w", err)
	}

	// Parse JSON
	var claims map[string]interface{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", fmt.Errorf("failed to parse JWT claims: %w", err)
	}

	// Get issuer (iss) field
	iss, ok := claims["iss"].(string)
	if !ok {
		return "", fmt.Errorf("missing 'iss' field in token")
	}

	// Extract environment from issuer (e.g., "cspm.dev.accuknox.com" -> "dev")
	parts = strings.Split(iss, ".")
	if len(parts) < 2 {
		return "", fmt.Errorf("invalid issuer format: %s", iss)
	}

	environment := parts[1]

	// Get base URL for environment
	baseURL, ok := envURLs[environment]
	if !ok {
		return "", fmt.Errorf("invalid environment: %s. Valid environments: dev, stage, demo, prod", environment)
	}

	return baseURL, nil
}

// GetName returns the plugin's unique identifier
func GetName() string {
	return PluginName
}

// TransportInterceptor modifies raw HTTP headers and body
func TransportInterceptor(ctx *context.Context, url string, headers map[string]string, body map[string]any) (map[string]string, map[string]any, error) {
	// Not used for this plugin
	return headers, body, nil
}

// PreHook is called before the request is sent to the provider
// This is where we extract and log the INPUT (prompt)
func PreHook(ctx *context.Context, req *schemas.BifrostRequest) (*schemas.BifrostRequest, *schemas.PluginShortCircuit, error) {
	if !pluginConfig.Enabled {
		return req, nil, nil
	}

	log.Println("[AccuKnox Plugin] PreHook called")

	// Extract request metadata
	provider, model, _ := req.GetRequestFields()

	// Get request ID from context
	requestID := "unknown"
	if ctx != nil {
		if id, ok := (*ctx).Value(schemas.BifrostContextKeyRequestID).(string); ok {
			requestID = id
		}
	}

	// Extract input based on request type
	var inputContent string
	var inputMessages []schemas.ChatMessage

	switch req.RequestType {
	case schemas.ChatCompletionRequest, schemas.ChatCompletionStreamRequest:
		if req.ChatRequest != nil && req.ChatRequest.Input != nil {
			inputMessages = req.ChatRequest.Input
			inputContent = extractMessagesContent(inputMessages)
		}
	case schemas.TextCompletionRequest, schemas.TextCompletionStreamRequest:
		if req.TextCompletionRequest != nil {
			if req.TextCompletionRequest.Input.PromptStr != nil {
				inputContent = *req.TextCompletionRequest.Input.PromptStr
			}
		}
	}

	// Log the extracted input
	log.Println("=" + strings.Repeat("=", 80))
	log.Printf("[AccuKnox Plugin] REQUEST ID: %s", requestID)
	log.Printf("[AccuKnox Plugin] Provider: %s", provider)
	log.Printf("[AccuKnox Plugin] Model: %s", model)
	log.Printf("[AccuKnox Plugin] Request Type: %s", req.RequestType)
	log.Printf("[AccuKnox Plugin] Timestamp: %s", time.Now().Format(time.RFC3339))
	log.Println("[AccuKnox Plugin] INPUT PROMPT:")
	log.Println(inputContent)
	log.Println(strings.Repeat("=", 81))

	// Store input content for PostHook
	promptCache[requestID] = inputContent

	// Send to AccuKnox API for prompt scanning
	if accuknoxClient != nil {
		sessionID, err := accuknoxClient.scanPrompt(inputContent)
		if err != nil {
			log.Printf("[AccuKnox Plugin] ERROR: Failed to scan prompt: %v", err)
		} else {
			log.Printf("[AccuKnox Plugin] Prompt scanned successfully, session_id: %s", sessionID)
			// Store session ID in context for PostHook
			if ctx != nil {
				*ctx = context.WithValue(*ctx, "accuknox_session_id", sessionID)
			}
		}
	}

	return req, nil, nil
}

// PostHook is called after receiving a response from the provider
// This is where we extract and log the OUTPUT (response)
func PostHook(ctx *context.Context, resp *schemas.BifrostResponse, bifrostErr *schemas.BifrostError) (*schemas.BifrostResponse, *schemas.BifrostError, error) {
	if !pluginConfig.Enabled {
		return resp, bifrostErr, nil
	}

	log.Println("[AccuKnox Plugin] PostHook called")

	// Get request ID from context
	requestID := "unknown"
	if ctx != nil {
		if id, ok := (*ctx).Value(schemas.BifrostContextKeyRequestID).(string); ok {
			requestID = id
		}
	}

	// Handle errors
	if bifrostErr != nil {
		log.Println("=" + strings.Repeat("=", 80))
		log.Printf("[AccuKnox Plugin] REQUEST ID: %s", requestID)
		log.Println("[AccuKnox Plugin] ERROR RESPONSE:")
		log.Printf("Error: %+v", bifrostErr)
		log.Println(strings.Repeat("=", 81))
		return resp, bifrostErr, nil
	}

	// Extract output based on response type
	var outputContent string
	var tokenUsage *schemas.BifrostLLMUsage

	if resp != nil {
		// Extract from ChatResponse
		if resp.ChatResponse != nil {
			if len(resp.ChatResponse.Choices) > 0 {
				choice := resp.ChatResponse.Choices[0]
				if choice.ChatNonStreamResponseChoice != nil && choice.ChatNonStreamResponseChoice.Message != nil {
					if choice.ChatNonStreamResponseChoice.Message.Content != nil &&
						choice.ChatNonStreamResponseChoice.Message.Content.ContentStr != nil {
						outputContent = *choice.ChatNonStreamResponseChoice.Message.Content.ContentStr
					}
				}
			}
			tokenUsage = resp.ChatResponse.Usage
		}

		// Extract from TextCompletionResponse
		if resp.TextCompletionResponse != nil {
			if len(resp.TextCompletionResponse.Choices) > 0 {
				choice := resp.TextCompletionResponse.Choices[0]
				if choice.TextCompletionResponseChoice != nil {
					outputContent = *choice.TextCompletionResponseChoice.Text
				}
			}
			tokenUsage = resp.TextCompletionResponse.Usage
		}
	}

	// Log the extracted output
	log.Println("=" + strings.Repeat("=", 80))
	log.Printf("[AccuKnox Plugin] REQUEST ID: %s", requestID)
	log.Printf("[AccuKnox Plugin] Timestamp: %s", time.Now().Format(time.RFC3339))
	log.Println("[AccuKnox Plugin] OUTPUT RESPONSE:")
	log.Println(outputContent)

	if tokenUsage != nil {
		log.Printf("[AccuKnox Plugin] Token Usage - Prompt: %d, Completion: %d, Total: %d",
			tokenUsage.PromptTokens, tokenUsage.CompletionTokens, tokenUsage.TotalTokens)
	}

	if resp != nil {
		extraFields := resp.GetExtraFields()
		log.Printf("[AccuKnox Plugin] Latency: %d ms", extraFields.Latency)
	}

	log.Println(strings.Repeat("=", 81))

	// Send to AccuKnox API for response scanning
	if accuknoxClient != nil && resp != nil {
		// Get session ID from context
		sessionID := ""
		if ctx != nil {
			if id, ok := (*ctx).Value("accuknox_session_id").(string); ok {
				sessionID = id
			}
		}

		// Get original prompt from cache
		originalPrompt := promptCache[requestID]

		err := accuknoxClient.scanResponse(originalPrompt, outputContent, sessionID)
		if err != nil {
			log.Printf("[AccuKnox Plugin] ERROR: Failed to scan response: %v", err)
		} else {
			log.Printf("[AccuKnox Plugin] Response scanned successfully")
		}

		// Clean up cache
		delete(promptCache, requestID)
	}

	return resp, bifrostErr, nil
}

// Cleanup is called when Bifrost shuts down
func Cleanup() error {
	log.Println("[AccuKnox Plugin] Cleanup called")
	return nil
}

// Helper function to extract content from multiple messages
func extractMessagesContent(messages []schemas.ChatMessage) string {
	var builder strings.Builder

	for i, msg := range messages {
		if i > 0 {
			builder.WriteString("\n")
		}

		if msg.Content != nil {
			if msg.Content.ContentStr != nil {
				builder.WriteString(*msg.Content.ContentStr)
			} else if msg.Content.ContentBlocks != nil {
				for _, block := range msg.Content.ContentBlocks {
					if block.Text != nil {
						builder.WriteString(*block.Text)
					}
				}
			}
		}
	}

	return builder.String()
}

// scanPrompt sends prompt to AccuKnox API for scanning
func (c *AccuKnoxClient) scanPrompt(content string) (string, error) {
	payload := map[string]interface{}{
		"query_type": "prompt",
		"content":    content,
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("failed to marshal payload: %w", err)
	}

	req, err := http.NewRequest("POST", c.baseURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.apiKey))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User", c.userInfo)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("API returned status %d: %s", resp.StatusCode, string(body))
	}

	// Parse response to get session_id
	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", fmt.Errorf("failed to parse response: %w", err)
	}

	sessionID, ok := result["session_id"].(string)
	if !ok {
		return "", fmt.Errorf("session_id not found in response")
	}

	return sessionID, nil
}

// scanResponse sends response to AccuKnox API for scanning
func (c *AccuKnoxClient) scanResponse(prompt, content, sessionID string) error {
	payload := map[string]interface{}{
		"query_type": "response",
		"prompt":     prompt,
		"content":    content,
		"session_id": sessionID,
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	req, err := http.NewRequest("POST", c.baseURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.apiKey))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User", c.userInfo)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("API returned status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}
