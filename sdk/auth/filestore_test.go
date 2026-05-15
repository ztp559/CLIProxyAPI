package auth

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	kiroauth "github.com/router-for-me/CLIProxyAPI/v7/internal/auth/kiro"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

func TestExtractAccessToken(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		metadata map[string]any
		expected string
	}{
		{
			"antigravity top-level access_token",
			map[string]any{"access_token": "tok-abc"},
			"tok-abc",
		},
		{
			"gemini nested token.access_token",
			map[string]any{
				"token": map[string]any{"access_token": "tok-nested"},
			},
			"tok-nested",
		},
		{
			"top-level takes precedence over nested",
			map[string]any{
				"access_token": "tok-top",
				"token":        map[string]any{"access_token": "tok-nested"},
			},
			"tok-top",
		},
		{
			"empty metadata",
			map[string]any{},
			"",
		},
		{
			"whitespace-only access_token",
			map[string]any{"access_token": "   "},
			"",
		},
		{
			"wrong type access_token",
			map[string]any{"access_token": 12345},
			"",
		},
		{
			"token is not a map",
			map[string]any{"token": "not-a-map"},
			"",
		},
		{
			"nested whitespace-only",
			map[string]any{
				"token": map[string]any{"access_token": "  "},
			},
			"",
		},
		{
			"fallback to nested when top-level empty",
			map[string]any{
				"access_token": "",
				"token":        map[string]any{"access_token": "tok-fallback"},
			},
			"tok-fallback",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := extractAccessToken(tt.metadata)
			if got != tt.expected {
				t.Errorf("extractAccessToken() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestFileTokenStoreSaveDoesNotInjectKiroSecretsIntoMetadata(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	store := NewFileTokenStore()
	store.SetBaseDir(dir)

	auth := &cliproxyauth.Auth{
		ID:       "kiro-google-test.json",
		Provider: kiroauth.ProviderKey,
		FileName: "kiro-google-test.json",
		Storage: &kiroauth.TokenStorage{
			AccessToken:    "secret-access",
			RefreshToken:   "secret-refresh",
			ProfileARN:     "arn:aws:iam::123456789012:role/test",
			ExpiresAt:      "2026-01-01T00:00:00Z",
			AuthMethod:     "social",
			SocialProvider: "Google",
			Region:         "us-east-1",
		},
		Metadata: map[string]any{
			"type":            kiroauth.ProviderKey,
			"auth_method":     "social",
			"social_provider": "Google",
			"region":          "us-east-1",
		},
	}

	path, err := store.Save(context.Background(), auth)
	if err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	if path != filepath.Join(dir, "kiro-google-test.json") {
		t.Fatalf("Save() path = %q", path)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	var saved map[string]any
	if err := json.Unmarshal(raw, &saved); err != nil {
		t.Fatalf("saved JSON is invalid: %v", err)
	}
	meta, _ := saved["metadata"].(map[string]any)
	if _, ok := meta["access_token"]; ok {
		t.Fatalf("metadata contains access_token: %#v", meta)
	}
	if _, ok := meta["refresh_token"]; ok {
		t.Fatalf("metadata contains refresh_token: %#v", meta)
	}
	if saved["access_token"] != "secret-access" || saved["refresh_token"] != "secret-refresh" {
		t.Fatalf("token storage did not retain credentials: %#v", saved)
	}
}
