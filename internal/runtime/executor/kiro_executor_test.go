package executor

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	kiroauth "github.com/router-for-me/CLIProxyAPI/v7/internal/auth/kiro"

	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
)

// testKiroAuth creates a minimal Auth with Kiro OAuth credentials for testing.
func testKiroAuth(t *testing.T, accessToken, refreshToken, region string) *cliproxyauth.Auth {
	t.Helper()
	auth := &cliproxyauth.Auth{
		ID:       "test-kiro-auth",
		Provider: "kiro",
		Status:   cliproxyauth.StatusActive,
		Metadata: map[string]any{
			"access_token":  accessToken,
			"refresh_token": refreshToken,
			"region":        region,
			"type":          "kiro",
		},
		Attributes: map[string]string{
			"access_token":  accessToken,
			"refresh_token": refreshToken,
		},
		Storage: &kiroauth.TokenStorage{
			AccessToken:  accessToken,
			RefreshToken: refreshToken,
			Region:       region,
		},
	}
	if region == "" {
		auth.Metadata["region"] = kiroauth.DefaultRegion
	}
	return auth
}

func TestKiroExecutor_Identifier(t *testing.T) {
	tests := []struct {
		provider string
		want     string
	}{
		{"kiro", "kiro"},
		{"claude-kiro-oauth", "claude-kiro-oauth"},
		{"KIRO", "kiro"},
		{"", "kiro"},
	}
	for _, tt := range tests {
		t.Run(tt.provider, func(t *testing.T) {
			e := NewKiroExecutor(nil, tt.provider)
			if got := e.Identifier(); got != tt.want {
				t.Errorf("Identifier() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestKiroExecutor_NewKiroExecutorDefaults(t *testing.T) {
	e := NewKiroExecutor(nil, "")
	if got := e.Identifier(); got != "kiro" {
		t.Errorf("default Identifier() = %q, want %q", got, "kiro")
	}
}

func TestKiroCreds_AccessToken(t *testing.T) {
	auth := testKiroAuth(t, "sk-ant-oat-VGVzdEFjY2Vzc1Rva2Vu", "rt-test-refresh", "us-east-1")
	tok, _, _, err := kiroCreds(auth)
	if err != nil {
		t.Fatalf("kiroCreds() error = %v", err)
	}
	if tok != "sk-ant-oat-VGVzdEFjY2Vzc1Rva2Vu" {
		t.Errorf("access token = %q, want %q", tok, "sk-ant-oat-VGVzdEFjY2Vzc1Rva2Vu")
	}
}

func TestKiroCreds_RefreshToken(t *testing.T) {
	auth := testKiroAuth(t, "sk-ant-oat-access", "rt-refresh-value", "us-east-1")
	_, refresh, _, err := kiroCreds(auth)
	if err != nil {
		t.Fatalf("kiroCreds() error = %v", err)
	}
	if refresh != "rt-refresh-value" {
		t.Errorf("refresh token = %q, want %q", refresh, "rt-refresh-value")
	}
}

func TestKiroCreds_EmptyAccessToken(t *testing.T) {
	auth := testKiroAuth(t, "", "rt-refresh", "us-east-1")
	_, _, _, err := kiroCreds(auth)
	if err == nil {
		t.Fatal("expected error for empty access token")
	}
}

func TestKiroGenerateURL_DefaultRegion(t *testing.T) {
	auth := testKiroAuth(t, "tok", "rt", "")
	got := kiroGenerateURL(auth)
	want := "https://q.us-east-1.amazonaws.com/generateAssistantResponse"
	if got != want {
		t.Errorf("kiroGenerateURL() = %q, want %q", got, want)
	}
}

func TestKiroGenerateURL_CustomRegion(t *testing.T) {
	auth := testKiroAuth(t, "tok", "rt", "eu-west-1")
	got := kiroGenerateURL(auth)
	want := "https://q.eu-west-1.amazonaws.com/generateAssistantResponse"
	if got != want {
		t.Errorf("kiroGenerateURL() = %q, want %q", got, want)
	}
}

func TestKiroGenerateURL_BaseURLOverride(t *testing.T) {
	auth := testKiroAuth(t, "tok", "rt", "us-east-1")
	auth.Attributes["base_url"] = "https://custom.example.com/generate"
	got := kiroGenerateURL(auth)
	want := "https://custom.example.com/generate"
	if got != want {
		t.Errorf("kiroGenerateURL() with base_url override = %q, want %q", got, want)
	}
}

func TestKiroModelName_Default(t *testing.T) {
	if got := kiroModelName(""); got != kiroDefaultModel {
		t.Errorf("kiroModelName() = %q, want %q", got, kiroDefaultModel)
	}
}

func TestKiroModelName_WithModel(t *testing.T) {
	if got := kiroModelName("claude-sonnet-4"); got != "claude-sonnet-4" {
		t.Errorf("kiroModelName() = %q, want %q", got, "claude-sonnet-4")
	}
}

func TestKiroModelName_KeepsModel(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"claude-sonnet-4", "claude-sonnet-4"},
		{"claude-sonnet-4.5", "claude-sonnet-4.5"},
		{"claude-opus-4", "claude-opus-4"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := kiroModelName(tt.input); got != tt.want {
				t.Errorf("kiroModelName() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestKiroProfileARN_FromMetadata(t *testing.T) {
	auth := testKiroAuth(t, "tok", "rt", "")
	auth.Metadata["profile_arn"] = "arn:aws:iam::12345:role/test"
	if got := kiroProfileARN(auth); got != "arn:aws:iam::12345:role/test" {
		t.Errorf("kiroProfileARN() = %q, want %q", got, "arn:aws:iam::12345:role/test")
	}
}

func TestKiroProfileARN_FromAttributes(t *testing.T) {
	auth := testKiroAuth(t, "tok", "rt", "")
	auth.Attributes["profile_arn"] = "arn:aws:iam::67890:role/test2"
	if got := kiroProfileARN(auth); got != "arn:aws:iam::67890:role/test2" {
		t.Errorf("kiroProfileARN() = %q, want %q", got, "arn:aws:iam::67890:role/test2")
	}
}

func TestKiroProfileARN_Empty(t *testing.T) {
	auth := testKiroAuth(t, "tok", "rt", "")
	if got := kiroProfileARN(auth); got != "" {
		t.Errorf("kiroProfileARN() = %q, want empty", got)
	}
}

func TestBuildKiroRequest_BasicUserMessage(t *testing.T) {
	payload := `{"model":"claude-sonnet-4","messages":[{"role":"user","content":[{"type":"text","text":"Hello, Kiro!"}]}]}`
	auth := testKiroAuth(t, "tok", "rt", "")
	body, err := buildKiroRequest([]byte(payload), "claude-sonnet-4", auth, nil)
	if err != nil {
		t.Fatalf("buildKiroRequest() error = %v", err)
	}
	var req map[string]any
	if err := json.Unmarshal(body, &req); err != nil {
		t.Fatalf("json.Unmarshal(body) error = %v", err)
	}
	cs, ok := req["conversationState"].(map[string]any)
	if !ok {
		t.Fatal("missing conversationState")
	}
	cm, ok := cs["currentMessage"].(map[string]any)
	if !ok {
		t.Fatal("missing currentMessage")
	}
	uim, ok := cm["userInputMessage"].(map[string]any)
	if !ok {
		t.Fatal("missing userInputMessage")
	}
	content, _ := uim["content"].(string)
	if !strings.Contains(content, "Hello, Kiro!") {
		t.Errorf("content = %q, want to contain %q", content, "Hello, Kiro!")
	}
	modelID, _ := uim["modelId"].(string)
	if !strings.Contains(modelID, "claude-sonnet") {
		t.Errorf("modelId = %q, want to contain %q", modelID, "claude-sonnet")
	}
	if _, ok := req["profileArn"]; ok {
		t.Error("profileArn should not be present when empty")
	}
}

func TestBuildKiroRequest_WithSystemPrompt(t *testing.T) {
	payload := `{"model":"claude-sonnet-4","system":"You are a helpful assistant.","messages":[{"role":"user","content":[{"type":"text","text":"Hi"}]}]}`
	auth := testKiroAuth(t, "tok", "rt", "")
	body, err := buildKiroRequest([]byte(payload), "claude-sonnet-4", auth, nil)
	if err != nil {
		t.Fatalf("buildKiroRequest() error = %v", err)
	}
	var req map[string]any
	if err := json.Unmarshal(body, &req); err != nil {
		t.Fatalf("json.Unmarshal error = %v", err)
	}
	cs := req["conversationState"].(map[string]any)
	cm := cs["currentMessage"].(map[string]any)
	uim := cm["userInputMessage"].(map[string]any)
	content, _ := uim["content"].(string)
	if !strings.Contains(content, "helpful assistant") && !strings.Contains(content, "You are") {
		t.Errorf("content = %q, want system prompt to be prepended", content)
	}
}

func TestBuildKiroRequest_WithProfileARN(t *testing.T) {
	payload := `{"model":"claude-sonnet-4","messages":[{"role":"user","content":[{"type":"text","text":"Hi"}]}]}`
	auth := testKiroAuth(t, "tok", "rt", "")
	auth.Metadata["profile_arn"] = "arn:aws:iam::12345:role/test"
	body, err := buildKiroRequest([]byte(payload), "claude-sonnet-4", auth, nil)
	if err != nil {
		t.Fatalf("buildKiroRequest() error = %v", err)
	}
	var req map[string]any
	if err := json.Unmarshal(body, &req); err != nil {
		t.Fatalf("json.Unmarshal error = %v", err)
	}
	arn, _ := req["profileArn"].(string)
	if arn != "arn:aws:iam::12345:role/test" {
		t.Errorf("profileArn = %q, want %q", arn, "arn:aws:iam::12345:role/test")
	}
}

func TestBuildKiroRequest_WithTools(t *testing.T) {
	payload := `{"model":"claude-sonnet-4","messages":[{"role":"user","content":[{"type":"text","text":"List files"}]}],"tools":[{"name":"bash","description":"Run bash commands","input_schema":{"type":"object","properties":{}}}]}`
	auth := testKiroAuth(t, "tok", "rt", "")
	body, err := buildKiroRequest([]byte(payload), "claude-sonnet-4", auth, nil)
	if err != nil {
		t.Fatalf("buildKiroRequest() error = %v", err)
	}
	var req map[string]any
	if err := json.Unmarshal(body, &req); err != nil {
		t.Fatalf("json.Unmarshal error = %v", err)
	}
	cs := req["conversationState"].(map[string]any)
	cm := cs["currentMessage"].(map[string]any)
	uim := cm["userInputMessage"].(map[string]any)
	ctxVal, ok := uim["userInputMessageContext"].(map[string]any)
	if !ok {
		t.Fatal("missing userInputMessageContext")
	}
	tools, ok := ctxVal["tools"].([]any)
	if !ok {
		t.Fatal("missing tools in context")
	}
	if len(tools) == 0 {
		t.Fatal("tools slice is empty")
	}
	toolSpec := tools[0].(map[string]any)
	ts := toolSpec["toolSpecification"].(map[string]any)
	name, _ := ts["name"].(string)
	if name != "bash" {
		t.Errorf("tool name = %q, want %q", name, "bash")
	}
}

func TestBuildKiroRequest_WithHistory(t *testing.T) {
	payload := `{"model":"claude-sonnet-4","messages":[{"role":"user","content":[{"type":"text","text":"First"}]},{"role":"assistant","content":[{"type":"text","text":"Response to first"}]},{"role":"user","content":[{"type":"text","text":"Second"}]}]}`
	auth := testKiroAuth(t, "tok", "rt", "")
	body, err := buildKiroRequest([]byte(payload), "claude-sonnet-4", auth, nil)
	if err != nil {
		t.Fatalf("buildKiroRequest() error = %v", err)
	}
	var req map[string]any
	if err := json.Unmarshal(body, &req); err != nil {
		t.Fatalf("json.Unmarshal error = %v", err)
	}
	cs := req["conversationState"].(map[string]any)
	history, ok := cs["history"].([]any)
	if !ok || len(history) == 0 {
		t.Fatal("expected non-empty history")
	}
	last := history[len(history)-1].(map[string]any)
	if _, ok := last["assistantResponseMessage"]; !ok {
		t.Error("last history entry should be assistantResponseMessage")
	}
}

func TestKiroResponseToClaude_Basic(t *testing.T) {
	data := []byte(`{"content":"Hello from Kiro!","toolUses":[]}`)
	result, usage := kiroResponseToClaude(data, "claude-sonnet-4", nil)
	var msg map[string]any
	if err := json.Unmarshal(result, &msg); err != nil {
		t.Fatalf("json.Unmarshal error = %v", err)
	}
	if msg["type"] != "message" {
		t.Errorf("type = %v, want %q", msg["type"], "message")
	}
	if msg["model"] != "claude-sonnet-4" {
		t.Errorf("model = %v, want %q", msg["model"], "claude-sonnet-4")
	}
	content, _ := msg["content"].([]any)
	if len(content) == 0 {
		t.Fatal("empty content")
	}
	block := content[0].(map[string]any)
	text, _ := block["text"].(string)
	if !strings.Contains(text, "Hello from Kiro") {
		t.Errorf("text = %q, want to contain %q", text, "Hello from Kiro")
	}
	if usage.InputTokens <= 0 {
		t.Error("usage.InputTokens should be > 0")
	}
}

func TestKiroCountTokens_Approx(t *testing.T) {
	data := []byte(`{"hello":"world","foo":"bar"}`)
	n := countKiroApproxTokens(data)
	if n <= 0 {
		t.Errorf("countKiroApproxTokens() = %d, want > 0", n)
	}
}

func TestKiroExecutor_Refresh_SetsMetadata(t *testing.T) {
	e := NewKiroExecutor(nil, "kiro")
	auth := testKiroAuth(t, "tok", "rt", "us-east-1")
	result, err := e.Refresh(context.Background(), auth)
	if err == nil {
		t.Fatal("expected error (no actual refresh), got nil")
	}
	if result != nil {
		t.Error("Refresh returned non-nil result on error")
	}
}

func TestKiroExecutor_Refresh_MissingToken(t *testing.T) {
	e := NewKiroExecutor(nil, "kiro")
	auth := testKiroAuth(t, "tok", "", "us-east-1")
	_, err := e.Refresh(context.Background(), auth)
	if err == nil {
		t.Fatal("expected error for missing refresh token")
	}
}

func TestShortenKiroToolName_ShortName(t *testing.T) {
	name := "bash"
	got := shortenKiroToolName(name)
	if got != name {
		t.Errorf("shortenKiroToolName(%q) = %q, want %q", name, got, name)
	}
}

func TestShortenKiroToolName_LongName(t *testing.T) {
	name := ""
	for i := 0; i < 100; i++ {
		name += "x"
	}
	got := shortenKiroToolName(name)
	if len(got) > kiroMaxToolNameLength {
		t.Errorf("shortened name length = %d, want <= %d", len(got), kiroMaxToolNameLength)
	}
	if !strings.Contains(got, "_") {
		t.Error("shortened name should contain hash suffix with underscore")
	}
}

func TestNonEmpty_Fallback(t *testing.T) {
	if got := nonEmpty("", "fallback"); got != "fallback" {
		t.Errorf("nonEmpty() = %q, want %q", got, "fallback")
	}
	if got := nonEmpty("value", "fallback"); got != "value" {
		t.Errorf("nonEmpty() = %q, want %q", got, "value")
	}
}

func TestFirstNonEmpty(t *testing.T) {
	if got := firstNonEmpty("", "", "third", "fourth"); got != "third" {
		t.Errorf("firstNonEmpty() = %q, want %q", got, "third")
	}
	if got := firstNonEmpty("", "", ""); got != "" {
		t.Errorf("firstNonEmpty() all empty = %q, want empty", got)
	}
}

func TestUniqueStrings(t *testing.T) {
	in := []string{"a", "b", "a", "c", "b", ""}
	got := uniqueStrings(in)
	want := []string{"a", "b", "c"}
	if len(got) != len(want) {
		t.Fatalf("uniqueStrings() len = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("uniqueStrings()[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestCountTokens(t *testing.T) {
	e := NewKiroExecutor(nil, "kiro")
	auth := testKiroAuth(t, "tok", "rt", "")
	req := cliproxyexecutor.Request{
		Payload: []byte(`{"model":"claude-sonnet-4","messages":[{"role":"user","content":"hello"}]}`),
	}
	opts := cliproxyexecutor.Options{
		SourceFormat: sdktranslator.FromString("openai"),
	}
	resp, err := e.CountTokens(context.Background(), auth, req, opts)
	if err != nil {
		t.Fatalf("CountTokens() error = %v", err)
	}
	if len(resp.Payload) == 0 {
		t.Error("CountTokens() returned empty payload")
	}
}

func TestKiroExecutor_Execute_NonStreamErrors(t *testing.T) {
	e := NewKiroExecutor(nil, "kiro")
	auth := testKiroAuth(t, "tok", "rt", "")
	auth.Attributes["base_url"] = "http://127.0.0.1:1/invalid"
	req := cliproxyexecutor.Request{
		Payload: []byte(`{"model":"claude-sonnet-4","messages":[{"role":"user","content":"hi"}]}`),
	}
	opts := cliproxyexecutor.Options{
		SourceFormat: sdktranslator.FromString("claude"),
	}
	_, err := e.Execute(context.Background(), auth, req, opts)
	if err == nil {
		t.Fatal("Execute() expected error with invalid URL, got nil")
	}
}

func TestKiroExecutor_ExecuteStream_NonStreamErrors(t *testing.T) {
	e := NewKiroExecutor(nil, "kiro")
	auth := testKiroAuth(t, "tok", "rt", "")
	auth.Attributes["base_url"] = "http://127.0.0.1:1/invalid"
	req := cliproxyexecutor.Request{
		Payload: []byte(`{"model":"claude-sonnet-4","messages":[{"role":"user","content":"hi"}]}`),
	}
	opts := cliproxyexecutor.Options{
		SourceFormat: sdktranslator.FromString("claude"),
	}
	_, err := e.ExecuteStream(context.Background(), auth, req, opts)
	if err == nil {
		t.Fatal("ExecuteStream() expected error with invalid URL, got nil")
	}
}

func TestKiroExecutor_Execute_CompactAltError(t *testing.T) {
	e := NewKiroExecutor(nil, "kiro")
	_, err := e.Execute(context.Background(), nil, cliproxyexecutor.Request{}, cliproxyexecutor.Options{Alt: "responses/compact"})
	if err == nil {
		t.Fatal("expected error for responses/compact")
	}
}

func TestKiroExecutor_ExecuteStream_CompactAltError(t *testing.T) {
	e := NewKiroExecutor(nil, "kiro")
	_, err := e.ExecuteStream(context.Background(), nil, cliproxyexecutor.Request{}, cliproxyexecutor.Options{Alt: "responses/compact"})
	if err == nil {
		t.Fatal("expected error for responses/compact")
	}
}

func TestKiroToolNameMap_RegisterShortName(t *testing.T) {
	tm := newKiroToolNameMap()
	tm.Register("bash")
	if len(tm.shortToOrig) != 0 {
		t.Error("short names should not be registered")
	}
}

func TestKiroToolNameMap_RegisterAndRestore(t *testing.T) {
	tm := newKiroToolNameMap()
	longName := ""
	for i := 0; i < 100; i++ {
		longName += "x"
	}
	tm.Register(longName)
	short := shortenKiroToolName(longName)
	if got := tm.Restore(short); got != longName {
		t.Errorf("Restore(%q) = %q, want %q", short, got, longName)
	}
}

func TestKiroToolNameMap_RestoreUnknown(t *testing.T) {
	tm := newKiroToolNameMap()
	if got := tm.Restore("unknown"); got != "unknown" {
		t.Errorf("Restore(unknown) = %q, want %q", got, "unknown")
	}
}

func TestKiroToolNameMap_NilSafe(t *testing.T) {
	var tm *kiroToolNameMap
	if got := tm.Restore("something"); got != "something" {
		t.Errorf("nil Restore = %q, want %q", got, "something")
	}
}

func TestBuildKiroToolNameMapFromClaudeBody(t *testing.T) {
	body := []byte(`{"tools":[{"name":"very_long_tool_name_that_exceeds_64_characters_abcdefghijklmnop"}],"messages":[{"role":"assistant","content":[{"type":"tool_use","name":"another_very_long_tool_name_that_also_exceeds_64_characters_qrstuvwxyz"}]}]}`)
	tm := buildKiroToolNameMapFromClaudeBody(body)
	short1 := shortenKiroToolName("very_long_tool_name_that_exceeds_64_characters_abcdefghijklmnop")
	short2 := shortenKiroToolName("another_very_long_tool_name_that_also_exceeds_64_characters_qrstuvwxyz")
	if got := tm.Restore(short1); got != "very_long_tool_name_that_exceeds_64_characters_abcdefghijklmnop" {
		t.Errorf("tool Restore = %q, want original", got)
	}
	if got := tm.Restore(short2); got != "another_very_long_tool_name_that_also_exceeds_64_characters_qrstuvwxyz" {
		t.Errorf("tool_use Restore = %q, want original", got)
	}
}

func TestKiroModelName_NormalizesDashVersion(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"claude-sonnet-4-5", "claude-sonnet-4.5"},
		{"claude-sonnet-4-6", "claude-sonnet-4.6"},
		{"claude-opus-4-5", "claude-opus-4.5"},
		{"claude-opus-4-6", "claude-opus-4.6"},
		{"claude-opus-4-7", "claude-opus-4.7"},
		{"claude-haiku-4-5", "claude-haiku-4.5"},
		{"claude-opus-4-5-20251101", "claude-opus-4.5"},
		{"claude-sonnet-4-5-20250929", "claude-sonnet-4.5"},
		{"claude-haiku-4-5-20251001", "claude-haiku-4.5"},
		{"claude-sonnet-4", "claude-sonnet-4"},
		{"", "claude-sonnet-4.5"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := kiroModelName(tt.input); got != tt.want {
				t.Errorf("kiroModelName(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestKiroResponseToClaude_RestoresToolNames(t *testing.T) {
	tm := newKiroToolNameMap()
	origName := ""
	for i := 0; i < 100; i++ {
		origName += "x"
	}
	tm.Register(origName)
	shortName := shortenKiroToolName(origName)
	data := []byte(`{"content":"Using tools","toolUses":[{"name":"` + shortName + `","toolUseId":"tu123","input":{"cmd":"ls"}}]}`)
	result, _ := kiroResponseToClaude(data, "claude-sonnet-4", tm)
	var msg map[string]any
	if err := json.Unmarshal(result, &msg); err != nil {
		t.Fatalf("json.Unmarshal error = %v", err)
	}
	content, _ := msg["content"].([]any)
	found := false
	for _, c := range content {
		block, _ := c.(map[string]any)
		if block["type"] == "tool_use" {
			name, _ := block["name"].(string)
			if name == origName {
				found = true
			} else {
				t.Errorf("tool_use name = %q, want original %q", name, origName)
			}
		}
	}
	if !found {
		t.Error("no tool_use block found with restored name")
	}
}

func TestKiroURLViaAuthBaseURL(t *testing.T) {
	// Ensure the helper function returns the expected URL.
	got := kiroauth.NormalizeRegion("us-west-2")
	if got != "us-west-2" {
		t.Errorf("NormalizeRegion() = %q, want %q", got, "us-west-2")
	}
	got2 := kiroauth.NormalizeRegion("")
	if got2 != kiroauth.DefaultRegion {
		t.Errorf("NormalizeRegion(empty) = %q, want %q", got2, kiroauth.DefaultRegion)
	}
}
