package main

import (
	"bufio"
	"bytes"
	"compress/flate"
	"compress/gzip"
	"context"
	"cursor-deepseek/masker"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/andybalholm/brotli"
	"golang.org/x/net/http2"
)

var (
	// deepseekEndpoint  = "https://api.deepseek.com"
	// deepseekChatModel = "deepseek-chat"
	// gpt4oModel        = "gpt-4o"
	deepseekEndpoint  = os.Getenv("DEEPSEEK_ENDPOINT")
	deepseekChatModel = os.Getenv("DEEPSEEK_CHAT_MODEL")
	model             = os.Getenv("MODEL")
)

// Uses ad prefix to API key: secret@apikey
var secret string

// var port = "9000"
var port = os.Getenv("PORT")
var useMask = false
var debug = false

func init() {
	// Get DeepSeek API key
	secret = os.Getenv("SECRET")
	if secret == "" {
		log.Fatal("SECRET environment variable is required")
	}
	if newPort := os.Getenv("PORT"); newPort != "" {
		port = newPort
	}
	if newUseMask := os.Getenv("USE_MASK"); newUseMask == "true" {
		useMask = true
	}
	if os.Getenv("DEBUG") == "true" {
		debug = true
	}
	// Default port
	if port == "" {
		port = "9000"
	}
}

// Add a debug logging helper
func debugLog(format string, v ...interface{}) {
	if debug {
		log.Printf(format, v...)
	}
}

func errorLog(format string, v ...interface{}) {
	log.Printf(format, v...)
}

// Models response structure
type ModelsResponse struct {
	Object string  `json:"object"`
	Data   []Model `json:"data"`
}

type Model struct {
	ID      string `json:"id"`
	Object  string `json:"object"`
	Created int64  `json:"created"`
	OwnedBy string `json:"owned_by"`
}

// OpenAI compatible request structure
type ChatRequest struct {
	Model       string      `json:"model"`
	Messages    []Message   `json:"messages"`
	Stream      bool        `json:"stream"`
	Functions   []Function  `json:"functions,omitempty"`
	Tools       []Tool      `json:"tools,omitempty"`
	ToolChoice  interface{} `json:"tool_choice,omitempty"`
	Temperature *float64    `json:"temperature,omitempty"`
	MaxTokens   *int        `json:"max_tokens,omitempty"`
}

type Message struct {
	Role       string     `json:"role"`
	Content    string     `json:"content"`
	ToolCalls  []ToolCall `json:"tool_calls,omitempty"`
	ToolCallID string     `json:"tool_call_id,omitempty"`
	Name       string     `json:"name,omitempty"`
}

type Function struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Parameters  any    `json:"parameters"`
}

type Tool struct {
	Type     string   `json:"type"`
	Function Function `json:"function"`
}

type ToolCall struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"function"`
}

// getAPIKey parse api key and extract DeepSeek API key from it
func getAPIKey(s string) string {
	// if !strings.Contains(s, "@") {
	// 	return s
	// }
	parts := strings.Split(s, "@")
	if len(parts) != 2 {
		return ""
	}
	if parts[0] != secret {
		return ""
	}
	return parts[1]
}

func convertToolChoice(choice interface{}) string {
	if choice == nil {
		return ""
	}

	// If string "auto" or "none"
	if str, ok := choice.(string); ok {
		switch str {
		case "auto", "none":
			return str
		}
	}

	// Try to parse as map for function call
	if choiceMap, ok := choice.(map[string]interface{}); ok {
		if choiceMap["type"] == "function" {
			return "auto" // DeepSeek doesn't support specific function selection, default to auto
		}
	}

	return ""
}

func convertMessages(messages []Message) []Message {
	converted := make([]Message, len(messages))
	for i, msg := range messages {
		debugLog("Converting message %d - Role: %s", i, msg.Role)
		converted[i] = msg

		// Apply masking to user messages if enabled
		if useMask && msg.Role == "user" {
			converted[i].Content = masker.Mask(msg.Content)
		}

		// Handle assistant messages with tool calls
		if msg.Role == "assistant" && len(msg.ToolCalls) > 0 {
			debugLog("Processing assistant message with %d tool calls", len(msg.ToolCalls))
			// DeepSeek expects tool_calls in a specific format
			toolCalls := make([]ToolCall, len(msg.ToolCalls))
			for j, tc := range msg.ToolCalls {
				toolCalls[j] = ToolCall{
					ID:       tc.ID,
					Type:     "function",
					Function: tc.Function,
				}
				debugLog("Tool call %d - ID: %s, Function: %s", j, tc.ID, tc.Function.Name)
			}
			converted[i].ToolCalls = toolCalls
		}

		// Handle function response messages
		if msg.Role == "function" {
			debugLog("Converting function response to tool response")
			// Convert to tool response format
			converted[i].Role = "tool"
		}
	}

	// Log the final converted messages
	for i, msg := range converted {
		debugLog("Final message %d - Role: %s, Content: %s", i, msg.Role, truncateString(msg.Content, 50))
		if len(msg.ToolCalls) > 0 {
			debugLog("Message %d has %d tool calls", i, len(msg.ToolCalls))
		}
	}

	return converted
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// DeepSeek request structure
type DeepSeekRequest struct {
	Model       string    `json:"model"`
	Messages    []Message `json:"messages"`
	Stream      bool      `json:"stream"`
	Temperature float64   `json:"temperature,omitempty"`
	MaxTokens   int       `json:"max_tokens,omitempty"`
	Tools       []Tool    `json:"tools,omitempty"`
	ToolChoice  string    `json:"tool_choice,omitempty"`
}

func main() {
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds | log.Lshortfile)

	server := &http.Server{
		Addr:    ":" + port,
		Handler: http.HandlerFunc(proxyHandler),
	}

	// Enable HTTP/2 support
	http2.ConfigureServer(server, &http2.Server{})

	log.Printf("Starting proxy server on %s", server.Addr)
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

func enableCors(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Origin, Content-Type, Accept, Authorization")
	w.Header().Set("Access-Control-Expose-Headers", "Content-Length")
	w.Header().Set("Access-Control-Allow-Credentials", "true")
}

func proxyHandler(w http.ResponseWriter, r *http.Request) {
	debugLog("Received request: %s %s", r.Method, r.URL.Path)

	if r.Method == "OPTIONS" {
		enableCors(w, r)
		return
	}

	enableCors(w, r)

	// Extract API key from Authorization header
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		errorLog("No Authorization header found")
		http.Error(w, "Authorization header is required", http.StatusUnauthorized)
		return
	}

	// Expecting format: "Bearer <token>"
	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		errorLog("Invalid Authorization header format")
		http.Error(w, "Invalid Authorization header format", http.StatusUnauthorized)
		return
	}

	deepseekAPIKey := getAPIKey(parts[1])
	if deepseekAPIKey == "" {
		errorLog("Empty or wrong API key in Authorization header")
		http.Error(w, "API key is required", http.StatusUnauthorized)
		return
	}

	// Handle /v1/models endpoint
	if r.URL.Path == "/v1/models" && r.Method == "GET" {
		debugLog("Handling /v1/models request")
		handleModelsRequest(w)
		return
	}

	// Log headers for debugging
	debugLog("Request headers: %+v", r.Header)

	// Read and log request body for debugging
	var chatReq ChatRequest
	body, err := io.ReadAll(r.Body)
	if err != nil {
		errorLog("Error reading request body: %v", err)
		http.Error(w, "Error reading request", http.StatusBadRequest)
		return
	}
	r.Body = io.NopCloser(bytes.NewBuffer(body))

	if err := json.Unmarshal(body, &chatReq); err != nil {
		errorLog("Error parsing request JSON: %v", err)
		debugLog("Raw request body: %s", string(body))
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	debugLog("Parsed request: %+v", chatReq)

	// Handle models endpoint
	if r.URL.Path == "/v1/models" {
		handleModelsRequest(w)
		return
	}

	// Modify the target URL to always add /v1
	targetPath := r.URL.Path
	if !strings.HasPrefix(targetPath, "/v1/") {
		targetPath = "/v1" + targetPath
	}

	// Only handle API requests with /v1/ prefix
	if !strings.HasPrefix(r.URL.Path, "/v1/") {
		errorLog("Invalid path: %s", r.URL.Path)
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}

	// Restore the body for further reading
	r.Body = io.NopCloser(bytes.NewBuffer(body))

	debugLog("Request body: %s", string(body))

	// Parse the request to check for streaming - reuse existing chatReq
	if err := json.Unmarshal(body, &chatReq); err != nil {
		errorLog("Error parsing request JSON: %v", err)
		http.Error(w, "Error parsing request", http.StatusBadRequest)
		return
	}

	debugLog("Requested model: %s", chatReq.Model)

	// Replace gpt-4o model with deepseek-chat
	if chatReq.Model == model {
		chatReq.Model = deepseekChatModel
		debugLog("Model converted to: %s", deepseekChatModel)
	} else {
		errorLog("Unsupported model requested: %s", chatReq.Model)
		http.Error(w, fmt.Sprintf("Model %s not supported. Use %s instead.", chatReq.Model, model), http.StatusBadRequest)
		return
	}

	// Convert to DeepSeek request format
	deepseekReq := DeepSeekRequest{
		Model:    deepseekChatModel,
		Messages: convertMessages(chatReq.Messages),
		Stream:   chatReq.Stream,
	}

	// Copy optional parameters if present
	if chatReq.Temperature != nil {
		deepseekReq.Temperature = *chatReq.Temperature
	}
	if chatReq.MaxTokens != nil {
		deepseekReq.MaxTokens = *chatReq.MaxTokens
	}

	// Handle tools/functions
	if len(chatReq.Tools) > 0 {
		deepseekReq.Tools = chatReq.Tools
		if tc := convertToolChoice(chatReq.ToolChoice); tc != "" {
			deepseekReq.ToolChoice = tc
		}
	} else if len(chatReq.Functions) > 0 {
		// Convert functions to tools format
		tools := make([]Tool, len(chatReq.Functions))
		for i, fn := range chatReq.Functions {
			tools[i] = Tool{
				Type:     "function",
				Function: fn,
			}
		}
		deepseekReq.Tools = tools

		// Convert tool_choice if present
		if tc := convertToolChoice(chatReq.ToolChoice); tc != "" {
			deepseekReq.ToolChoice = tc
		}
	}

	// Create new request body
	modifiedBody, err := json.Marshal(deepseekReq)
	if err != nil {
		errorLog("Error creating modified request body: %v", err)
		http.Error(w, "Error creating modified request", http.StatusInternalServerError)
		return
	}

	debugLog("Modified request body: %s", string(modifiedBody))

	// Create the proxy request to DeepSeek
	targetURL := deepseekEndpoint + targetPath
	if r.URL.RawQuery != "" {
		targetURL += "?" + r.URL.RawQuery
	}

	debugLog("Forwarding to: %s", targetURL)
	proxyReq, err := http.NewRequest(r.Method, targetURL, bytes.NewReader(modifiedBody))
	if err != nil {
		errorLog("Error creating proxy request: %v", err)
		http.Error(w, "Error creating proxy request", http.StatusInternalServerError)
		return
	}

	// Copy headers
	copyHeaders(proxyReq.Header, r.Header)

	// Set DeepSeek API key and content type
	proxyReq.Header.Set("Authorization", "Bearer "+deepseekAPIKey)
	proxyReq.Header.Set("Content-Type", "application/json")
	if chatReq.Stream {
		proxyReq.Header.Set("Accept", "text/event-stream")
	}

	// Add Accept-Language header from request
	if acceptLanguage := r.Header.Get("Accept-Language"); acceptLanguage != "" {
		proxyReq.Header.Set("Accept-Language", acceptLanguage)
	}

	debugLog("Proxy request headers: %v", proxyReq.Header)

	// Create a custom client with keepalive
	client := &http.Client{
		Transport: &http2.Transport{
			AllowHTTP: true,
			DialTLS:   nil,
		},
		Timeout: 5 * time.Minute,
	}

	// Send the request
	resp, err := client.Do(proxyReq)
	if err != nil {
		errorLog("Error forwarding request: %v", err)
		http.Error(w, "Error forwarding request", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	debugLog("DeepSeek response status: %d", resp.StatusCode)
	debugLog("DeepSeek response headers: %v", resp.Header)

	// Handle error responses
	if resp.StatusCode >= 400 {
		respBody, err := io.ReadAll(resp.Body)
		if err != nil {
			errorLog("Error reading error response: %v", err)
			http.Error(w, "Error reading response", http.StatusInternalServerError)
			return
		}
		debugLog("DeepSeek error response: %s", string(respBody))

		// Forward the error response
		for k, v := range resp.Header {
			w.Header()[k] = v
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(resp.StatusCode)
		w.Write(respBody)
		return
	}

	// Handle streaming response
	if chatReq.Stream {
		handleStreamingResponse(w, resp)
		return
	}

	// Handle regular response
	handleRegularResponse(w, resp)
}

func handleStreamingResponse(w http.ResponseWriter, resp *http.Response) {
	debugLog("Starting streaming response handling")
	debugLog("Response status: %d", resp.StatusCode)
	debugLog("Response headers: %+v", resp.Header)

	// Set headers for streaming response
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(resp.StatusCode)

	// Create a buffered reader for the response body
	reader := bufio.NewReader(resp.Body)

	// Create a context to track the client connection
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create a channel to detect client disconnection
	clientClosed := w.(http.CloseNotifier).CloseNotify()

	// Start a goroutine to send heartbeats
	go func() {
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				// Send a heartbeat comment
				if _, err := w.Write([]byte(": heartbeat\n\n")); err != nil {
					debugLog("Error sending heartbeat: %v", err)
					cancel()
					return
				}
				if f, ok := w.(http.Flusher); ok {
					f.Flush()
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	for {
		select {
		case <-ctx.Done():
			debugLog("Context cancelled, ending stream")
			return
		case <-clientClosed:
			debugLog("Client closed connection")
			cancel()
			return
		default:
			line, err := reader.ReadBytes('\n')
			if err != nil {
				if err == io.EOF {
					continue
				}
				debugLog("Error reading stream: %v", err)
				cancel()
				return
			}

			// Skip empty lines
			if len(bytes.TrimSpace(line)) == 0 {
				continue
			}

			// Write the line to the response
			if _, err := w.Write(line); err != nil {
				debugLog("Error writing to response: %v", err)
				cancel()
				return
			}

			// Flush the response writer
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			} else {
				debugLog("Warning: ResponseWriter does not support Flush")
			}
		}
	}
}

func handleRegularResponse(w http.ResponseWriter, resp *http.Response) {
	debugLog("Handling regular (non-streaming) response")
	debugLog("Response status: %d", resp.StatusCode)
	debugLog("Response headers: %+v", resp.Header)

	// Read and log response body
	body, err := readResponse(resp)
	if err != nil {
		debugLog("Error reading response: %v", err)
		http.Error(w, "Error reading response from upstream", http.StatusInternalServerError)
		return
	}

	debugLog("Original response body: %s", string(body))

	// Parse the DeepSeek response
	var deepseekResp struct {
		ID      string `json:"id"`
		Object  string `json:"object"`
		Created int64  `json:"created"`
		Model   string `json:"model"`
		Choices []struct {
			Index        int     `json:"index"`
			Message      Message `json:"message"`
			FinishReason string  `json:"finish_reason"`
		} `json:"choices"`
		Usage struct {
			PromptTokens     int `json:"prompt_tokens"`
			CompletionTokens int `json:"completion_tokens"`
			TotalTokens      int `json:"total_tokens"`
		} `json:"usage"`
	}

	if err := json.Unmarshal(body, &deepseekResp); err != nil {
		debugLog("Error parsing DeepSeek response: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Convert to OpenAI format
	openAIResp := struct {
		ID      string `json:"id"`
		Object  string `json:"object"`
		Created int64  `json:"created"`
		Model   string `json:"model"`
		Choices []struct {
			Index        int     `json:"index"`
			Message      Message `json:"message"`
			FinishReason string  `json:"finish_reason"`
		} `json:"choices"`
		Usage struct {
			PromptTokens     int `json:"prompt_tokens"`
			CompletionTokens int `json:"completion_tokens"`
			TotalTokens      int `json:"total_tokens"`
		} `json:"usage"`
	}{
		ID:      deepseekResp.ID,
		Object:  "chat.completion",
		Created: deepseekResp.Created,
		Model:   model, // Use the original model name
		Usage:   deepseekResp.Usage,
	}

	// Convert choices and ensure tool calls are properly handled
	openAIResp.Choices = make([]struct {
		Index        int     `json:"index"`
		Message      Message `json:"message"`
		FinishReason string  `json:"finish_reason"`
	}, len(deepseekResp.Choices))

	for i, choice := range deepseekResp.Choices {
		openAIResp.Choices[i] = struct {
			Index        int     `json:"index"`
			Message      Message `json:"message"`
			FinishReason string  `json:"finish_reason"`
		}{
			Index:        choice.Index,
			Message:      choice.Message,
			FinishReason: choice.FinishReason,
		}

		// Ensure tool calls are properly formatted in the message
		if len(choice.Message.ToolCalls) > 0 {
			debugLog("Processing %d tool calls in choice %d", len(choice.Message.ToolCalls), i)
			for j, tc := range choice.Message.ToolCalls {
				debugLog("Tool call %d: %+v", j, tc)
				// Ensure the tool call has the required fields
				if tc.Function.Name == "" {
					debugLog("Warning: Empty function name in tool call %d", j)
					continue
				}
				// Keep the tool call as is since it's already in the correct format
				openAIResp.Choices[i].Message.ToolCalls = append(openAIResp.Choices[i].Message.ToolCalls, tc)
			}
		}
	}

	// Convert back to JSON
	modifiedBody, err := json.Marshal(openAIResp)
	if err != nil {
		debugLog("Error creating modified response: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	debugLog("Modified response body: %s", string(modifiedBody))

	// Set response headers
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	w.Write(modifiedBody)
	debugLog("Modified response sent successfully")
}

func copyHeaders(dst, src http.Header) {
	// Headers to skip
	skipHeaders := map[string]bool{
		"Content-Length":    true,
		"Content-Encoding":  true,
		"Transfer-Encoding": true,
		"Connection":        true,
	}

	for k, vv := range src {
		if !skipHeaders[k] {
			for _, v := range vv {
				dst.Add(k, v)
			}
		}
	}
}

func handleModelsRequest(w http.ResponseWriter) {
	debugLog("Handling models request")
	response := ModelsResponse{
		Object: "list",
		Data: []Model{
			{
				ID:      "gpt-4o",
				Object:  "model",
				Created: time.Now().Unix(),
				OwnedBy: "openai",
			},
			{
				ID:      "deepseek-chat",
				Object:  "model",
				Created: time.Now().Unix(),
				OwnedBy: "deepseek",
			},
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
	debugLog("Models response sent successfully")
}

func readResponse(resp *http.Response) ([]byte, error) {
	var reader io.Reader = resp.Body

	switch resp.Header.Get("Content-Encoding") {
	case "gzip":
		gzReader, err := gzip.NewReader(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("error creating gzip reader: %v", err)
		}
		defer gzReader.Close()
		reader = gzReader
	case "br":
		reader = brotli.NewReader(resp.Body)
	case "deflate":
		reader = flate.NewReader(resp.Body)
	}

	return io.ReadAll(reader)
}
