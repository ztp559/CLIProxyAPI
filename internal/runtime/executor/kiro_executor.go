package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	kiroauth "github.com/router-for-me/CLIProxyAPI/v7/internal/auth/kiro"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/runtime/executor/helps"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/thinking"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/util"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/usage"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
	log "github.com/sirupsen/logrus"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

const (
	kiroDefaultModel        = "claude-sonnet-4.5"
	kiroDefaultOrigin       = "AI_EDITOR"
	kiroChatTriggerManual   = "MANUAL"
	kiroMaxToolNameLength   = 64
	kiroPlaceholderToolName = "no_tool_available"
)

// KiroExecutor proxies Claude-compatible requests to the Kiro/Amazon Q assistant endpoint.
type KiroExecutor struct {
	cfg      *config.Config
	provider string
}

func NewKiroExecutor(cfg *config.Config, provider string) *KiroExecutor {
	provider = strings.ToLower(strings.TrimSpace(provider))
	if provider == "" {
		provider = kiroauth.ProviderKey
	}
	return &KiroExecutor{cfg: cfg, provider: provider}
}

func (e *KiroExecutor) Identifier() string { return e.provider }

func (e *KiroExecutor) Execute(ctx context.Context, auth *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (resp cliproxyexecutor.Response, err error) {
	if opts.Alt == "responses/compact" {
		return resp, statusErr{code: http.StatusNotImplemented, msg: "/responses/compact not supported"}
	}
	baseModel := kiroModelName(req.Model)
	token, _, _, err := kiroCreds(auth)
	if err != nil {
		return resp, err
	}

	reporter := helps.NewUsageReporter(ctx, e.Identifier(), baseModel, auth)
	defer reporter.TrackFailure(ctx, &err)

	from := opts.SourceFormat
	to := sdktranslator.FromString("claude")
	bodyForTranslation, bodyForUpstream, err := e.buildClaudePayload(ctx, auth, req, opts, false)
	if err != nil {
		return resp, err
	}
	kiroBody, err := buildKiroRequest(bodyForUpstream, baseModel, auth)
	if err != nil {
		return resp, err
	}

	url := kiroGenerateURL(auth)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(kiroBody))
	if err != nil {
		return resp, err
	}
	applyKiroHeaders(httpReq, auth, token)
	recordKiroRequest(ctx, e.cfg, httpReq, kiroBody, e.Identifier(), auth)

	httpResp, err := helps.NewUtlsHTTPClient(e.cfg, auth, 0).Do(httpReq)
	if err != nil {
		helps.RecordAPIResponseError(ctx, e.cfg, err)
		return resp, err
	}
	helps.RecordAPIResponseMetadata(ctx, e.cfg, httpResp.StatusCode, httpResp.Header.Clone())
	data, err := readKiroResponseBody(ctx, e.cfg, httpResp)
	if err != nil {
		return resp, err
	}
	if httpResp.StatusCode < 200 || httpResp.StatusCode >= 300 {
		err = statusErr{code: httpResp.StatusCode, msg: string(data)}
		return resp, err
	}

	claudePayload, usage := kiroResponseToClaude(data, baseModel)
	reporter.Publish(ctx, usage)
	var param any
	out := sdktranslator.TranslateNonStream(ctx, to, from, req.Model, opts.OriginalRequest, bodyForTranslation, claudePayload, &param)
	return cliproxyexecutor.Response{Payload: out, Headers: httpResp.Header.Clone()}, nil
}

func (e *KiroExecutor) ExecuteStream(ctx context.Context, auth *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (_ *cliproxyexecutor.StreamResult, err error) {
	if opts.Alt == "responses/compact" {
		return nil, statusErr{code: http.StatusNotImplemented, msg: "/responses/compact not supported"}
	}
	baseModel := kiroModelName(req.Model)
	token, _, _, err := kiroCreds(auth)
	if err != nil {
		return nil, err
	}
	reporter := helps.NewUsageReporter(ctx, e.Identifier(), baseModel, auth)
	defer reporter.TrackFailure(ctx, &err)

	from := opts.SourceFormat
	to := sdktranslator.FromString("claude")
	bodyForTranslation, bodyForUpstream, err := e.buildClaudePayload(ctx, auth, req, opts, true)
	if err != nil {
		return nil, err
	}
	kiroBody, err := buildKiroRequest(bodyForUpstream, baseModel, auth)
	if err != nil {
		return nil, err
	}

	url := kiroGenerateURL(auth)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(kiroBody))
	if err != nil {
		return nil, err
	}
	applyKiroHeaders(httpReq, auth, token)
	recordKiroRequest(ctx, e.cfg, httpReq, kiroBody, e.Identifier(), auth)

	httpResp, err := helps.NewUtlsHTTPClient(e.cfg, auth, 0).Do(httpReq)
	if err != nil {
		helps.RecordAPIResponseError(ctx, e.cfg, err)
		return nil, err
	}
	helps.RecordAPIResponseMetadata(ctx, e.cfg, httpResp.StatusCode, httpResp.Header.Clone())
	if httpResp.StatusCode < 200 || httpResp.StatusCode >= 300 {
		data, readErr := readKiroResponseBody(ctx, e.cfg, httpResp)
		if readErr != nil {
			return nil, readErr
		}
		err = statusErr{code: httpResp.StatusCode, msg: string(data)}
		return nil, err
	}

	decodedBody, err := decodeResponseBody(httpResp.Body, httpResp.Header.Get("Content-Encoding"))
	if err != nil {
		helps.RecordAPIResponseError(ctx, e.cfg, err)
		if errClose := httpResp.Body.Close(); errClose != nil {
			log.Errorf("response body close error: %v", errClose)
		}
		return nil, err
	}
	out := make(chan cliproxyexecutor.StreamChunk)
	go func() {
		defer close(out)
		defer func() {
			if errClose := decodedBody.Close(); errClose != nil {
				log.Errorf("response body close error: %v", errClose)
			}
		}()
		var param any
		streamKiroAsClaude(ctx, decodedBody, func(line []byte) bool {
			helps.AppendAPIResponseChunk(ctx, e.cfg, line)
			if detail, ok := helps.ParseClaudeStreamUsage(line); ok {
				reporter.Publish(ctx, detail)
			}
			if from == to {
				select {
				case out <- cliproxyexecutor.StreamChunk{Payload: append(bytes.Clone(line), '\n')}:
					return true
				case <-ctx.Done():
					return false
				}
			}
			chunks := sdktranslator.TranslateStream(ctx, to, from, req.Model, opts.OriginalRequest, bodyForTranslation, bytes.Clone(line), &param)
			for i := range chunks {
				select {
				case out <- cliproxyexecutor.StreamChunk{Payload: chunks[i]}:
				case <-ctx.Done():
					return false
				}
			}
			return true
		})
	}()
	return &cliproxyexecutor.StreamResult{Headers: httpResp.Header.Clone(), Chunks: out}, nil
}

func (e *KiroExecutor) Refresh(ctx context.Context, auth *cliproxyauth.Auth) (*cliproxyauth.Auth, error) {
	if auth == nil {
		return nil, fmt.Errorf("kiro executor: auth is nil")
	}
	_, refreshToken, region, err := kiroCreds(auth)
	if err != nil && strings.TrimSpace(refreshToken) == "" {
		return nil, err
	}
	refreshed, err := kiroauth.RefreshToken(ctx, e.cfg, auth.ProxyURL, refreshToken, region)
	if err != nil {
		return nil, err
	}
	if auth.Metadata == nil {
		auth.Metadata = map[string]any{}
	}
	auth.Metadata["access_token"] = refreshed.AccessToken
	auth.Metadata["accessToken"] = refreshed.AccessToken
	auth.Metadata["refresh_token"] = refreshed.RefreshToken
	auth.Metadata["refreshToken"] = refreshed.RefreshToken
	auth.Metadata["expires_at"] = refreshed.ExpiresAt
	auth.Metadata["expiresAt"] = refreshed.ExpiresAt
	auth.Metadata["type"] = auth.Provider
	auth.Metadata["region"] = refreshed.Region
	if refreshed.ProfileARN != "" {
		auth.Metadata["profile_arn"] = refreshed.ProfileARN
		auth.Metadata["profileArn"] = refreshed.ProfileARN
	}
	auth.Storage = refreshed
	auth.Provider = kiroauth.NormalizeProvider(auth.Provider)
	auth.Status = cliproxyauth.StatusActive
	auth.StatusMessage = ""
	auth.LastRefreshedAt = time.Now().UTC()
	return auth, nil
}

func (e *KiroExecutor) CountTokens(ctx context.Context, auth *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	baseModel := kiroModelName(req.Model)
	from := opts.SourceFormat
	to := sdktranslator.FromString("claude")
	body := sdktranslator.TranslateRequest(from, to, baseModel, req.Payload, false)
	return cliproxyexecutor.Response{Payload: sdktranslator.TranslateTokenCount(ctx, to, from, int64(countKiroApproxTokens(body)), opts.OriginalRequest)}, nil
}

func (e *KiroExecutor) HttpRequest(ctx context.Context, auth *cliproxyauth.Auth, req *http.Request) (*http.Response, error) {
	if req == nil {
		return nil, fmt.Errorf("kiro executor: request is nil")
	}
	token, _, _, err := kiroCreds(auth)
	if err != nil {
		return nil, err
	}
	httpReq := req.WithContext(ctx)
	applyKiroHeaders(httpReq, auth, token)
	return helps.NewUtlsHTTPClient(e.cfg, auth, 0).Do(httpReq)
}

func (e *KiroExecutor) buildClaudePayload(ctx context.Context, auth *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options, stream bool) ([]byte, []byte, error) {
	baseModel := kiroModelName(req.Model)
	from := opts.SourceFormat
	to := sdktranslator.FromString("claude")
	originalPayloadSource := req.Payload
	if len(opts.OriginalRequest) > 0 {
		originalPayloadSource = opts.OriginalRequest
	}
	originalTranslated := sdktranslator.TranslateRequest(from, to, baseModel, originalPayloadSource, stream)
	body := sdktranslator.TranslateRequest(from, to, baseModel, req.Payload, stream)
	body, _ = sjson.SetBytes(body, "model", baseModel)
	var err error
	body, err = thinking.ApplyThinking(body, req.Model, from.String(), to.String(), e.Identifier())
	if err != nil {
		return nil, nil, err
	}
	requestedModel := helps.PayloadRequestedModel(opts, req.Model)
	requestPath := helps.PayloadRequestPath(opts)
	body = helps.ApplyPayloadConfigWithRoot(e.cfg, baseModel, to.String(), "", body, originalTranslated, requestedModel, requestPath)
	body = ensureModelMaxTokens(body, baseModel)
	body = disableThinkingIfToolChoiceForced(body)
	body = normalizeClaudeTemperatureForThinking(body)
	if countCacheControls(body) == 0 {
		body = ensureCacheControl(body)
	}
	body = enforceCacheControlLimit(body, 4)
	body = normalizeCacheControlTTL(body)
	return body, body, nil
}

type kiroRequest struct {
	ConversationState kiroConversationState `json:"conversationState"`
	ProfileARN        string                `json:"profileArn,omitempty"`
}

type kiroConversationState struct {
	AgentTaskType   string             `json:"agentTaskType"`
	ChatTriggerType string             `json:"chatTriggerType"`
	ConversationID  string             `json:"conversationId"`
	CurrentMessage  kiroCurrentMessage `json:"currentMessage"`
	History         []map[string]any   `json:"history,omitempty"`
}

type kiroCurrentMessage struct {
	UserInputMessage kiroUserInputMessage `json:"userInputMessage"`
}

type kiroUserInputMessage struct {
	Content                 string         `json:"content"`
	ModelID                 string         `json:"modelId"`
	Origin                  string         `json:"origin"`
	Images                  []kiroImage    `json:"images,omitempty"`
	UserInputMessageContext map[string]any `json:"userInputMessageContext,omitempty"`
}

type kiroImage struct {
	Format string            `json:"format"`
	Source map[string]string `json:"source"`
}

type kiroToolUse struct {
	Input     any    `json:"input"`
	Name      string `json:"name"`
	ToolUseID string `json:"toolUseId"`
}

func buildKiroRequest(claudeBody []byte, model string, auth *cliproxyauth.Auth) ([]byte, error) {
	root := gjson.ParseBytes(claudeBody)
	messages := root.Get("messages").Array()
	if len(messages) == 0 {
		return nil, statusErr{code: http.StatusBadRequest, msg: "kiro executor: request has no messages"}
	}
	systemPrompt := claudeSystemText(root.Get("system"))
	tools := buildKiroTools(root.Get("tools"))
	history := make([]map[string]any, 0, len(messages))
	start := 0
	prependSystem := false
	if systemPrompt != "" {
		if len(messages) == 1 && messages[0].Get("role").String() == "user" {
			prependSystem = true
		} else if messages[0].Get("role").String() == "user" {
			content, _, _, _ := kiroUserParts(messages[0])
			history = append(history, map[string]any{"userInputMessage": map[string]any{"content": systemPrompt + "\n\n" + content, "modelId": model, "origin": kiroDefaultOrigin}})
			start = 1
		} else {
			history = append(history, map[string]any{"userInputMessage": map[string]any{"content": systemPrompt, "modelId": model, "origin": kiroDefaultOrigin}})
		}
	}
	for i := start; i < len(messages)-1; i++ {
		msg := messages[i]
		switch msg.Get("role").String() {
		case "user":
			content, toolResults, images, _ := kiroUserParts(msg)
			uim := map[string]any{"content": nonEmpty(content, "Continue"), "modelId": model, "origin": kiroDefaultOrigin}
			ctx := map[string]any{}
			if len(toolResults) > 0 {
				ctx["toolResults"] = uniqueKiroToolResults(toolResults)
			}
			if len(images) > 0 {
				uim["images"] = images
			}
			if len(ctx) > 0 {
				uim["userInputMessageContext"] = ctx
			}
			history = append(history, map[string]any{"userInputMessage": uim})
		case "assistant":
			history = append(history, map[string]any{"assistantResponseMessage": kiroAssistantMessage(msg)})
		}
	}
	if len(history) > 0 {
		if _, ok := history[len(history)-1]["assistantResponseMessage"]; !ok {
			history = append(history, map[string]any{"assistantResponseMessage": map[string]any{"content": "Continue"}})
		}
	}
	last := messages[len(messages)-1]
	currentContent := ""
	var currentToolResults []map[string]any
	var currentImages []kiroImage
	if last.Get("role").String() == "assistant" {
		history = append(history, map[string]any{"assistantResponseMessage": kiroAssistantMessage(last)})
		currentContent = "Continue"
	} else {
		currentContent, currentToolResults, currentImages, _ = kiroUserParts(last)
		if prependSystem {
			currentContent = nonEmpty(systemPrompt, "") + "\n\n" + currentContent
			currentContent = strings.TrimSpace(currentContent)
		}
		currentContent = nonEmpty(currentContent, func() string {
			if len(currentToolResults) > 0 {
				return "Tool results provided."
			}
			return "Continue"
		}())
	}
	ctx := map[string]any{}
	if len(currentToolResults) > 0 {
		ctx["toolResults"] = uniqueKiroToolResults(currentToolResults)
	}
	if len(tools) > 0 {
		ctx["tools"] = tools
	}
	current := kiroUserInputMessage{Content: currentContent, ModelID: model, Origin: kiroDefaultOrigin, Images: currentImages}
	if len(ctx) > 0 {
		current.UserInputMessageContext = ctx
	}
	kr := kiroRequest{ConversationState: kiroConversationState{AgentTaskType: "vibe", ChatTriggerType: kiroChatTriggerManual, ConversationID: uuid.NewString(), CurrentMessage: kiroCurrentMessage{UserInputMessage: current}, History: history}}
	if profile := kiroProfileARN(auth); profile != "" {
		kr.ProfileARN = profile
	}
	return json.Marshal(kr)
}

func claudeSystemText(v gjson.Result) string {
	if !v.Exists() {
		return ""
	}
	if v.Type == gjson.String {
		return v.String()
	}
	if v.IsArray() {
		parts := []string{}
		for _, p := range v.Array() {
			if p.Get("type").String() == "text" || p.Get("text").Exists() {
				parts = append(parts, p.Get("text").String())
			}
		}
		return strings.Join(parts, "\n")
	}
	return v.String()
}

func kiroUserParts(msg gjson.Result) (string, []map[string]any, []kiroImage, []kiroToolUse) {
	content := msg.Get("content")
	if content.Type == gjson.String {
		return content.String(), nil, nil, nil
	}
	texts := []string{}
	toolResults := []map[string]any{}
	images := []kiroImage{}
	toolUses := []kiroToolUse{}
	for _, part := range content.Array() {
		switch part.Get("type").String() {
		case "text":
			texts = append(texts, part.Get("text").String())
		case "tool_result":
			toolResults = append(toolResults, map[string]any{"content": []map[string]string{{"text": contentText(part.Get("content"))}}, "status": "success", "toolUseId": part.Get("tool_use_id").String()})
		case "image":
			mediaType := part.Get("source.media_type").String()
			format := strings.TrimPrefix(mediaType, "image/")
			if format == "" {
				format = "png"
			}
			data := part.Get("source.data").String()
			if data != "" {
				images = append(images, kiroImage{Format: format, Source: map[string]string{"bytes": data}})
			}
		case "tool_use":
			toolUses = append(toolUses, kiroToolUse{Input: jsonRawOrString(part.Get("input")), Name: shortenKiroToolName(part.Get("name").String()), ToolUseID: part.Get("id").String()})
		}
	}
	return strings.Join(texts, ""), toolResults, images, toolUses
}

func kiroAssistantMessage(msg gjson.Result) map[string]any {
	content := msg.Get("content")
	out := map[string]any{"content": ""}
	toolUses := []kiroToolUse{}
	if content.Type == gjson.String {
		out["content"] = content.String()
	} else {
		texts := []string{}
		for _, part := range content.Array() {
			switch part.Get("type").String() {
			case "text", "thinking":
				texts = append(texts, contentText(part))
			case "tool_use":
				toolUses = append(toolUses, kiroToolUse{Input: jsonRawOrString(part.Get("input")), Name: shortenKiroToolName(part.Get("name").String()), ToolUseID: part.Get("id").String()})
			}
		}
		out["content"] = strings.Join(texts, "")
	}
	if len(toolUses) > 0 {
		out["toolUses"] = toolUses
	}
	return out
}

func buildKiroTools(tools gjson.Result) []map[string]any {
	out := []map[string]any{}
	if tools.Exists() && tools.IsArray() {
		for _, tool := range tools.Array() {
			name := strings.ToLower(strings.TrimSpace(tool.Get("name").String()))
			if name == "" || name == "web_search" || name == "websearch" {
				continue
			}
			desc := strings.TrimSpace(tool.Get("description").String())
			if desc == "" {
				continue
			}
			if len(desc) > 9216 {
				desc = desc[:9216] + "..."
			}
			schemaRaw := tool.Get("input_schema").Raw
			var schema any = map[string]any{}
			if schemaRaw != "" {
				_ = json.Unmarshal([]byte(schemaRaw), &schema)
			}
			out = append(out, map[string]any{"toolSpecification": map[string]any{"name": shortenKiroToolName(tool.Get("name").String()), "description": desc, "inputSchema": map[string]any{"json": schema}}})
		}
	}
	if len(out) == 0 {
		out = append(out, map[string]any{"toolSpecification": map[string]any{"name": kiroPlaceholderToolName, "description": "This is a placeholder tool when no other tools are available. It does nothing.", "inputSchema": map[string]any{"json": map[string]any{"type": "object", "properties": map[string]any{}}}}})
	}
	return out
}

func kiroResponseToClaude(data []byte, model string) ([]byte, usage.Detail) {
	text, toolUses := parseKiroContentAndTools(data)
	content := []map[string]any{}
	if strings.TrimSpace(text) != "" {
		content = append(content, map[string]any{"type": "text", "text": text})
	}
	for _, tu := range toolUses {
		content = append(content, map[string]any{"type": "tool_use", "id": tu.ToolUseID, "name": tu.Name, "input": tu.Input})
	}
	if len(content) == 0 {
		content = append(content, map[string]any{"type": "text", "text": string(data)})
	}
	usageDetail := usage.Detail{InputTokens: int64(countKiroApproxTokens(data) / 2), OutputTokens: int64(countKiroApproxTokens([]byte(text)))}
	out := map[string]any{"id": "msg_" + uuid.NewString(), "type": "message", "role": "assistant", "model": model, "content": content, "stop_reason": "end_turn", "stop_sequence": nil, "usage": map[string]any{"input_tokens": usageDetail.InputTokens, "output_tokens": usageDetail.OutputTokens}}
	raw, _ := json.Marshal(out)
	return raw, usageDetail
}

type kiroStreamEvent struct {
	Content             *string         `json:"content,omitempty"`
	Name                *string         `json:"name,omitempty"`
	ToolUseID           *string         `json:"toolUseId,omitempty"`
	Input               json.RawMessage `json:"input,omitempty"`
	Stop                *bool           `json:"stop,omitempty"`
	ContextUsagePercent *float64        `json:"contextUsagePercentage,omitempty"`
}

type kiroStreamState struct {
	blockIndex   int
	textOpened   bool
	toolOpened   bool
	toolBlockIdx int
}

func streamKiroAsClaude(ctx context.Context, r io.Reader, emit func([]byte) bool) {
	model := kiroDefaultModel
	id := "msg_" + uuid.NewString()
	st := &kiroStreamState{}

	emit([]byte("event: message_start\ndata: " + mustJSON(map[string]any{"type": "message_start", "message": map[string]any{"id": id, "type": "message", "role": "assistant", "model": model, "content": []any{}, "stop_reason": nil, "stop_sequence": nil, "usage": map[string]any{"input_tokens": 0, "output_tokens": 0}}}) + "\n"))

	buf := make([]byte, 32768)
	remainder := []byte{}
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		n, readErr := r.Read(buf)
		if n > 0 {
			remainder = append(remainder, buf[:n]...)
			remainder = parseKiroStreamChunk(remainder, st, emit)
		}
		if readErr != nil {
			break
		}
	}

	closeKiroTextBlock(st, emit)
	closeKiroToolBlock(st, emit)
	emit([]byte("event: message_delta\ndata: " + mustJSON(map[string]any{"type": "message_delta", "delta": map[string]any{"stop_reason": "end_turn", "stop_sequence": nil}, "usage": map[string]any{"output_tokens": 0}}) + "\n"))
	emit([]byte("event: message_stop\ndata: " + mustJSON(map[string]any{"type": "message_stop"}) + "\n"))
}

func openKiroTextBlock(st *kiroStreamState, emit func([]byte) bool) {
	if st.textOpened {
		return
	}
	st.textOpened = true
	emit([]byte("event: content_block_start\ndata: " + mustJSON(map[string]any{"type": "content_block_start", "index": st.blockIndex, "content_block": map[string]any{"type": "text", "text": ""}}) + "\n"))
}

func closeKiroTextBlock(st *kiroStreamState, emit func([]byte) bool) {
	if !st.textOpened {
		return
	}
	st.textOpened = false
	emit([]byte("event: content_block_stop\ndata: " + mustJSON(map[string]any{"type": "content_block_stop", "index": st.blockIndex}) + "\n"))
	st.blockIndex++
}

func openKiroToolBlock(st *kiroStreamState, emit func([]byte) bool, name, toolUseID string, input any) {
	if st.toolOpened {
		closeKiroToolBlock(st, emit)
	}
	st.toolOpened = true
	st.toolBlockIdx = st.blockIndex
	emit([]byte("event: content_block_start\ndata: " + mustJSON(map[string]any{"type": "content_block_start", "index": st.blockIndex, "content_block": map[string]any{"type": "tool_use", "id": toolUseID, "name": name, "input": input}}) + "\n"))
}

func closeKiroToolBlock(st *kiroStreamState, emit func([]byte) bool) {
	if !st.toolOpened {
		return
	}
	st.toolOpened = false
	emit([]byte("event: content_block_stop\ndata: " + mustJSON(map[string]any{"type": "content_block_stop", "index": st.toolBlockIdx}) + "\n"))
	st.blockIndex++
	st.toolBlockIdx = -1
}

func parseKiroStreamChunk(data []byte, st *kiroStreamState, emit func([]byte) bool) []byte {
	if len(data) == 0 {
		return data
	}
	txt := string(data)
	searchStart := 0
	lastConsumed := 0

	for {
		jsonStart := strings.Index(txt[searchStart:], "{")
		if jsonStart < 0 {
			break
		}
		jsonStart += searchStart

		braceCount := 0
		jsonEnd := -1
		inString := false
		escapeNext := false

		for i := jsonStart; i < len(txt); i++ {
			ch := txt[i]
			if escapeNext {
				escapeNext = false
				continue
			}
			if ch == '\\' {
				escapeNext = true
				continue
			}
			if ch == '"' {
				inString = !inString
				continue
			}
			if !inString {
				if ch == '{' {
					braceCount++
				} else if ch == '}' {
					braceCount--
					if braceCount == 0 {
						jsonEnd = i
						break
					}
				}
			}
		}

		if jsonEnd < 0 {
			lastConsumed = jsonStart
			searchStart = jsonStart
			break
		}

		raw := txt[jsonStart : jsonEnd+1]
		lastConsumed = jsonEnd + 1
		searchStart = jsonEnd + 1

		var ev kiroStreamEvent
		if err := json.Unmarshal([]byte(raw), &ev); err != nil {
			continue
		}

		if ev.Content != nil && *ev.Content != "" {
			openKiroTextBlock(st, emit)
			if !emit([]byte("event: content_block_delta\ndata: " + mustJSON(map[string]any{"type": "content_block_delta", "index": st.blockIndex, "delta": map[string]any{"type": "text_delta", "text": *ev.Content}}) + "\n")) {
				return nil
			}
		} else if ev.Name != nil && ev.ToolUseID != nil {
			openKiroToolBlock(st, emit, *ev.Name, *ev.ToolUseID, normalizeKiroInput(ev.Input))
		} else if ev.Stop != nil && *ev.Stop {
			closeKiroToolBlock(st, emit)
		}
	}

	if lastConsumed >= len(txt) {
		return nil
	}
	return []byte(txt[lastConsumed:])
}

func normalizeKiroInput(raw json.RawMessage) any {
	if len(raw) == 0 {
		return map[string]any{}
	}
	var out any
	if err := json.Unmarshal(raw, &out); err == nil {
		return out
	}
	trimmed := strings.TrimSpace(string(raw))
	if len(trimmed) < 256 {
		return strings.TrimRight(trimmed, "\"")
	}
	return map[string]any{"text": trimmed}
}

func parseKiroContentAndTools(data []byte) (string, []kiroToolUse) {
	raw := string(data)
	texts := []string{}
	tools := []kiroToolUse{}
	if gjson.ValidBytes(data) {
		root := gjson.ParseBytes(data)
		collectKiroJSON(root, &texts, &tools)
	}
	for _, m := range []string{"content", "text", "message", "assistantResponseMessage.content", "response.content"} {
		v := gjson.GetBytes(data, m)
		if v.Exists() && v.Type == gjson.String {
			texts = append(texts, v.String())
		}
	}
	if len(texts) == 0 {
		texts = append(texts, parseKiroEventText(raw))
	}
	return strings.TrimSpace(strings.Join(uniqueStrings(texts), "")), tools
}

func collectKiroJSON(v gjson.Result, texts *[]string, tools *[]kiroToolUse) {
	if v.IsObject() {
		if c := v.Get("content"); c.Exists() && c.Type == gjson.String {
			*texts = append(*texts, c.String())
		}
		if c := v.Get("text"); c.Exists() && c.Type == gjson.String {
			*texts = append(*texts, c.String())
		}
		if name := v.Get("name"); name.Exists() && v.Get("toolUseId").Exists() {
			*tools = append(*tools, kiroToolUse{Name: name.String(), ToolUseID: v.Get("toolUseId").String(), Input: jsonRawOrString(v.Get("input"))})
		}
		v.ForEach(func(_, val gjson.Result) bool { collectKiroJSON(val, texts, tools); return true })
	} else if v.IsArray() {
		for _, item := range v.Array() {
			collectKiroJSON(item, texts, tools)
		}
	}
}

func parseKiroEventText(raw string) string {
	parts := []string{}
	for _, marker := range []string{":message-typeevent", "event"} {
		idx := 0
		for {
			pos := strings.Index(raw[idx:], marker)
			if pos < 0 {
				break
			}
			idx += pos + len(marker)
			rest := raw[idx:]
			start := strings.Index(rest, "{")
			if start < 0 {
				continue
			}
			js := rest[start:]
			end := strings.LastIndex(js, "}")
			if end < 0 {
				continue
			}
			text, _ := parseKiroContentAndTools([]byte(js[:end+1]))
			if text != "" {
				parts = append(parts, text)
			}
			break
		}
	}
	if len(parts) > 0 {
		return strings.Join(parts, "")
	}
	return raw
}

func readKiroResponseBody(ctx context.Context, cfg *config.Config, httpResp *http.Response) ([]byte, error) {
	decodedBody, err := decodeResponseBody(httpResp.Body, httpResp.Header.Get("Content-Encoding"))
	if err != nil {
		helps.RecordAPIResponseError(ctx, cfg, err)
		if errClose := httpResp.Body.Close(); errClose != nil {
			log.Errorf("response body close error: %v", errClose)
		}
		return nil, err
	}
	defer func() {
		if errClose := decodedBody.Close(); errClose != nil {
			log.Errorf("response body close error: %v", errClose)
		}
	}()
	data, err := io.ReadAll(decodedBody)
	if err != nil {
		helps.RecordAPIResponseError(ctx, cfg, err)
		return nil, err
	}
	helps.AppendAPIResponseChunk(ctx, cfg, data)
	return data, nil
}

func applyKiroHeaders(req *http.Request, auth *cliproxyauth.Auth, token string) {
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", kiroauth.KiroUserAgent)
	req.Header.Set("amz-sdk-invocation-id", uuid.NewString())
	req.Header.Set("amz-sdk-request", "attempt=1; max=3")
	if auth != nil {
		util.ApplyCustomHeadersFromAttrs(req, auth.Attributes)
	}
}

func recordKiroRequest(ctx context.Context, cfg *config.Config, req *http.Request, body []byte, provider string, auth *cliproxyauth.Auth) {
	var authID, authLabel, authType, authValue string
	if auth != nil {
		authID = auth.ID
		authLabel = auth.Label
		authType, authValue = auth.AccountInfo()
	}
	helps.RecordAPIRequest(ctx, cfg, helps.UpstreamRequestLog{URL: req.URL.String(), Method: req.Method, Headers: req.Header.Clone(), Body: body, Provider: provider, AuthID: authID, AuthLabel: authLabel, AuthType: authType, AuthValue: authValue})
}

func kiroCreds(a *cliproxyauth.Auth) (accessToken, refreshToken, region string, err error) {
	if a == nil {
		return "", "", kiroauth.DefaultRegion, fmt.Errorf("kiro executor: auth is nil")
	}
	region = kiroauth.NormalizeRegion(stringMeta(a, "region"))
	accessToken = firstNonEmpty(stringMeta(a, "access_token"), stringMeta(a, "accessToken"), stringAttr(a, "access_token"), stringAttr(a, "accessToken"))
	refreshToken = firstNonEmpty(stringMeta(a, "refresh_token"), stringMeta(a, "refreshToken"), stringAttr(a, "refresh_token"), stringAttr(a, "refreshToken"))
	if accessToken == "" {
		err = fmt.Errorf("kiro executor: access token is empty")
	}
	return
}

func kiroProfileARN(a *cliproxyauth.Auth) string {
	return firstNonEmpty(stringMeta(a, "profile_arn"), stringMeta(a, "profileArn"), stringAttr(a, "profile_arn"), stringAttr(a, "profileArn"))
}
func kiroGenerateURL(a *cliproxyauth.Auth) string {
	if base := firstNonEmpty(stringAttr(a, "base_url"), stringMeta(a, "base_url"), stringMeta(a, "baseUrl")); base != "" {
		return strings.TrimRight(base, "/")
	}
	region := kiroauth.NormalizeRegion(stringMeta(a, "region"))
	return fmt.Sprintf("https://q.%s.amazonaws.com/generateAssistantResponse", region)
}
func kiroModelName(model string) string {
	if v := strings.TrimSpace(thinking.ParseSuffix(model).ModelName); v != "" {
		return v
	}
	return kiroDefaultModel
}
func stringAttr(a *cliproxyauth.Auth, key string) string {
	if a != nil && a.Attributes != nil {
		return strings.TrimSpace(a.Attributes[key])
	}
	return ""
}
func stringMeta(a *cliproxyauth.Auth, key string) string {
	if a != nil && a.Metadata != nil {
		if v, ok := a.Metadata[key].(string); ok {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
func nonEmpty(v, fallback string) string {
	if strings.TrimSpace(v) != "" {
		return v
	}
	return fallback
}
func contentText(v gjson.Result) string {
	if v.Type == gjson.String {
		return v.String()
	}
	if t := v.Get("text"); t.Exists() {
		return t.String()
	}
	if v.IsArray() {
		parts := []string{}
		for _, p := range v.Array() {
			parts = append(parts, contentText(p))
		}
		return strings.Join(parts, "")
	}
	return v.String()
}
func jsonRawOrString(v gjson.Result) any {
	if !v.Exists() {
		return map[string]any{}
	}
	var out any
	if err := json.Unmarshal([]byte(v.Raw), &out); err == nil {
		return out
	}
	return v.String()
}
func uniqueStrings(in []string) []string {
	seen := map[string]struct{}{}
	out := []string{}
	for _, v := range in {
		if strings.TrimSpace(v) == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}
func uniqueKiroToolResults(in []map[string]any) []map[string]any {
	seen := map[string]struct{}{}
	out := []map[string]any{}
	for _, v := range in {
		id, _ := v["toolUseId"].(string)
		if id != "" {
			if _, ok := seen[id]; ok {
				continue
			}
			seen[id] = struct{}{}
		}
		out = append(out, v)
	}
	return out
}
func shortenKiroToolName(name string) string {
	name = strings.TrimSpace(name)
	if len(name) <= kiroMaxToolNameLength {
		return name
	}
	sum := uuid.NewSHA1(uuid.NameSpaceOID, []byte(name)).String()
	suffix := "_" + strings.ReplaceAll(sum[:8], "-", "")
	return name[:kiroMaxToolNameLength-len(suffix)] + suffix
}
func countKiroApproxTokens(data []byte) int {
	n := len(bytes.Fields(data))
	if n == 0 && len(data) > 0 {
		n = len(data) / 4
	}
	if n < 0 {
		return 0
	}
	return n
}
func mustJSON(v any) string { raw, _ := json.Marshal(v); return string(raw) }
