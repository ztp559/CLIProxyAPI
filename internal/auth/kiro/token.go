package kiro

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/misc"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/proxyutil"
)

const (
	ProviderKey       = "kiro"
	LegacyProviderKey = "claude-kiro-oauth"
	DefaultRegion     = "us-east-1"
	KiroUserAgent     = "KiroIDE"
)

var authServiceBaseURL = "https://prod.%s.auth.desktop.kiro.dev"

type TokenStorage struct {
	AccessToken    string         `json:"access_token"`
	RefreshToken   string         `json:"refresh_token"`
	ProfileARN     string         `json:"profile_arn,omitempty"`
	ExpiresAt      string         `json:"expires_at"`
	AuthMethod     string         `json:"auth_method,omitempty"`
	SocialProvider string         `json:"social_provider,omitempty"`
	Region         string         `json:"region,omitempty"`
	Type           string         `json:"type"`
	Metadata       map[string]any `json:"-"`
}

func (ts *TokenStorage) SetMetadata(meta map[string]any) { ts.Metadata = meta }

func (ts *TokenStorage) SaveTokenToFile(authFilePath string) error {
	misc.LogSavingCredentials(authFilePath)
	ts.Type = ProviderKey
	if err := os.MkdirAll(filepath.Dir(authFilePath), 0o700); err != nil {
		return fmt.Errorf("kiro token storage: create directory: %w", err)
	}
	data, err := misc.MergeMetadata(ts, ts.Metadata)
	if err != nil {
		return fmt.Errorf("kiro token storage: merge metadata: %w", err)
	}
	raw, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("kiro token storage: marshal: %w", err)
	}
	if err = os.WriteFile(authFilePath, append(raw, '\n'), 0o600); err != nil {
		return fmt.Errorf("kiro token storage: write file: %w", err)
	}
	return nil
}

type RefreshResponse struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
	ProfileARN   string `json:"profileArn"`
	ExpiresIn    int64  `json:"expiresIn"`
}

func NormalizeProvider(provider string) string {
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case LegacyProviderKey, "kiro-oauth":
		return ProviderKey
	default:
		if strings.TrimSpace(provider) == "" {
			return ProviderKey
		}
		return strings.ToLower(strings.TrimSpace(provider))
	}
}

func NormalizeRegion(region string) string {
	region = strings.TrimSpace(region)
	if region == "" {
		return DefaultRegion
	}
	return region
}

func AuthBaseURL(region string) string {
	return fmt.Sprintf(authServiceBaseURL, NormalizeRegion(region))
}

func RefreshToken(ctx context.Context, cfg *config.Config, proxyURL, refreshToken, region string) (*TokenStorage, error) {
	refreshToken = strings.TrimSpace(refreshToken)
	if refreshToken == "" {
		return nil, fmt.Errorf("kiro refresh: refresh token is empty")
	}
	region = NormalizeRegion(region)
	body, err := json.Marshal(map[string]string{"refreshToken": refreshToken})
	if err != nil {
		return nil, fmt.Errorf("kiro refresh: marshal request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, AuthBaseURL(region)+"/refreshToken", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("kiro refresh: create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", KiroUserAgent)

	client := &http.Client{Timeout: 30 * time.Second}
	proxySetting := strings.TrimSpace(proxyURL)
	if proxySetting == "" && cfg != nil {
		proxySetting = strings.TrimSpace(cfg.ProxyURL)
	}
	if transport, _, errTransport := proxyutil.BuildHTTPTransport(proxySetting); errTransport != nil {
		return nil, fmt.Errorf("kiro refresh: configure proxy: %w", errTransport)
	} else if transport != nil {
		client.Transport = transport
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("kiro refresh: request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("kiro refresh: read response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("kiro refresh: HTTP %d: %s", resp.StatusCode, string(respBody))
	}
	var parsed RefreshResponse
	if err = json.Unmarshal(respBody, &parsed); err != nil {
		return nil, fmt.Errorf("kiro refresh: decode response: %w", err)
	}
	if strings.TrimSpace(parsed.AccessToken) == "" {
		return nil, fmt.Errorf("kiro refresh: response missing accessToken")
	}
	expiresIn := parsed.ExpiresIn
	if expiresIn <= 0 {
		expiresIn = 3600
	}
	out := &TokenStorage{
		AccessToken:  parsed.AccessToken,
		RefreshToken: refreshToken,
		ProfileARN:   parsed.ProfileARN,
		ExpiresAt:    time.Now().UTC().Add(time.Duration(expiresIn) * time.Second).Format(time.RFC3339),
		AuthMethod:   "social",
		Region:       region,
		Type:         ProviderKey,
	}
	if strings.TrimSpace(parsed.RefreshToken) != "" {
		out.RefreshToken = parsed.RefreshToken
	}
	return out, nil
}
