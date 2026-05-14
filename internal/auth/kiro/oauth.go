package kiro

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/proxyutil"
)

type PKCECodes struct {
	CodeVerifier  string
	CodeChallenge string
}

type TokenExchangeResponse struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
	ProfileARN   string `json:"profileArn"`
	ExpiresIn    int64  `json:"expiresIn"`
}

func GeneratePKCECodes() (*PKCECodes, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return nil, fmt.Errorf("kiro oauth: generate verifier: %w", err)
	}
	verifier := base64.RawURLEncoding.EncodeToString(buf)
	hash := sha256.Sum256([]byte(verifier))
	return &PKCECodes{
		CodeVerifier:  verifier,
		CodeChallenge: base64.RawURLEncoding.EncodeToString(hash[:]),
	}, nil
}

func NormalizeSocialProvider(method string) (idp string, label string, err error) {
	switch strings.ToLower(strings.TrimSpace(method)) {
	case "", "google":
		return "Google", "google", nil
	case "github", "git-hub":
		return "Github", "github", nil
	default:
		return "", "", fmt.Errorf("kiro oauth: unsupported auth method %q", method)
	}
}

func BuildAuthURL(region, idp, redirectURI, state string, pkce *PKCECodes) (string, error) {
	if pkce == nil || pkce.CodeChallenge == "" {
		return "", fmt.Errorf("kiro oauth: missing PKCE challenge")
	}
	if strings.TrimSpace(redirectURI) == "" {
		return "", fmt.Errorf("kiro oauth: missing redirect URI")
	}
	values := url.Values{}
	values.Set("idp", idp)
	values.Set("redirect_uri", redirectURI)
	values.Set("code_challenge", pkce.CodeChallenge)
	values.Set("code_challenge_method", "S256")
	values.Set("state", state)
	values.Set("prompt", "select_account")
	return AuthBaseURL(region) + "/login?" + values.Encode(), nil
}

func ExchangeCode(ctx context.Context, cfg *config.Config, proxyURL, region, code, redirectURI string, pkce *PKCECodes, socialProvider string) (*TokenStorage, error) {
	code = strings.TrimSpace(code)
	if code == "" {
		return nil, fmt.Errorf("kiro oauth: code is empty")
	}
	if pkce == nil || pkce.CodeVerifier == "" {
		return nil, fmt.Errorf("kiro oauth: missing PKCE verifier")
	}
	region = NormalizeRegion(region)
	body, err := json.Marshal(map[string]string{
		"code":          code,
		"code_verifier": pkce.CodeVerifier,
		"redirect_uri":  redirectURI,
	})
	if err != nil {
		return nil, fmt.Errorf("kiro oauth: marshal token request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, AuthBaseURL(region)+"/oauth/token", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("kiro oauth: create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "CLIProxyAPI/kiro-oauth")
	client := &http.Client{Timeout: 30 * time.Second}
	proxySetting := strings.TrimSpace(proxyURL)
	if proxySetting == "" && cfg != nil {
		proxySetting = strings.TrimSpace(cfg.ProxyURL)
	}
	if transport, _, errTransport := proxyutil.BuildHTTPTransport(proxySetting); errTransport != nil {
		return nil, fmt.Errorf("kiro oauth: configure proxy: %w", errTransport)
	} else if transport != nil {
		client.Transport = transport
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("kiro oauth: token request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("kiro oauth: read token response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("kiro oauth: token exchange HTTP %d: %s", resp.StatusCode, string(respBody))
	}
	var parsed TokenExchangeResponse
	if err = json.Unmarshal(respBody, &parsed); err != nil {
		return nil, fmt.Errorf("kiro oauth: decode token response: %w", err)
	}
	if strings.TrimSpace(parsed.AccessToken) == "" || strings.TrimSpace(parsed.RefreshToken) == "" {
		return nil, fmt.Errorf("kiro oauth: token response missing accessToken or refreshToken")
	}
	expiresIn := parsed.ExpiresIn
	if expiresIn <= 0 {
		expiresIn = 3600
	}
	return &TokenStorage{
		AccessToken:    parsed.AccessToken,
		RefreshToken:   parsed.RefreshToken,
		ProfileARN:     parsed.ProfileARN,
		ExpiresAt:      time.Now().UTC().Add(time.Duration(expiresIn) * time.Second).Format(time.RFC3339),
		AuthMethod:     "social",
		SocialProvider: socialProvider,
		Region:         region,
		Type:           ProviderKey,
	}, nil
}
