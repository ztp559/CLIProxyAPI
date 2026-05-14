package kiro

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func TestNormalizeProvider(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"":                  ProviderKey,
		"kiro":              ProviderKey,
		"KIRO":              ProviderKey,
		"kiro-oauth":        ProviderKey,
		"claude-kiro-oauth": ProviderKey,
		"other":             "other",
	}
	for input, want := range cases {
		if got := NormalizeProvider(input); got != want {
			t.Fatalf("NormalizeProvider(%q)=%q want %q", input, got, want)
		}
	}
}

func TestNormalizeSocialProvider(t *testing.T) {
	t.Parallel()
	idp, label, err := NormalizeSocialProvider("github")
	if err != nil {
		t.Fatal(err)
	}
	if idp != "Github" || label != "github" {
		t.Fatalf("github normalized to %q/%q", idp, label)
	}
	idp, label, err = NormalizeSocialProvider("")
	if err != nil {
		t.Fatal(err)
	}
	if idp != "Google" || label != "google" {
		t.Fatalf("default normalized to %q/%q", idp, label)
	}
	if _, _, err = NormalizeSocialProvider("builder-id"); err == nil {
		t.Fatal("expected unsupported builder-id error")
	}
}

func TestBuildAuthURL(t *testing.T) {
	t.Parallel()
	pkce := &PKCECodes{CodeChallenge: "challenge"}
	u, err := BuildAuthURL("us-east-1", "Google", "http://127.0.0.1:19876/oauth/callback", "state", pkce)
	if err != nil {
		t.Fatal(err)
	}
	for _, part := range []string{
		"https://prod.us-east-1.auth.desktop.kiro.dev/login?",
		"idp=Google",
		"code_challenge=challenge",
		"code_challenge_method=S256",
		"state=state",
		"prompt=select_account",
	} {
		if !strings.Contains(u, part) {
			t.Fatalf("auth URL %q missing %q", u, part)
		}
	}
}

func TestGeneratePKCECodes(t *testing.T) {
	t.Parallel()
	codes, err := GeneratePKCECodes()
	if err != nil {
		t.Fatal(err)
	}
	if codes.CodeVerifier == "" || codes.CodeChallenge == "" {
		t.Fatalf("empty pkce fields: %#v", codes)
	}
	if strings.ContainsAny(codes.CodeVerifier+codes.CodeChallenge, "+/=") {
		t.Fatalf("PKCE fields should be raw base64url encoded: %#v", codes)
	}
}

func TestTokenStorageSaveTokenToFile(t *testing.T) {
	t.Parallel()
	token := &TokenStorage{
		AccessToken:    "access",
		RefreshToken:   "refresh",
		ProfileARN:     "profile",
		ExpiresAt:      time.Now().UTC().Add(time.Hour).Format(time.RFC3339),
		AuthMethod:     "social",
		SocialProvider: "google",
		Region:         "us-east-1",
	}
	p := t.TempDir() + "/kiro.json"
	if err := token.SaveTokenToFile(p); err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatal(err)
	}
	if raw["type"] != ProviderKey || raw["access_token"] != "access" || raw["refresh_token"] != "refresh" {
		t.Fatalf("unexpected saved token: %#v", raw)
	}
}

func TestRefreshToken(t *testing.T) {
	t.Parallel()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/refreshToken" {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"accessToken":"new-access","refreshToken":"new-refresh","profileArn":"profile","expiresIn":120}`))
	}))
	defer ts.Close()
	oldBase := authServiceBaseURL
	authServiceBaseURL = "%s"
	defer func() { authServiceBaseURL = oldBase }()
	out, err := RefreshToken(context.Background(), nil, "", "old-refresh", ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	if out.AccessToken != "new-access" || out.RefreshToken != "new-refresh" || out.ProfileARN != "profile" {
		t.Fatalf("unexpected refresh output: %#v", out)
	}
}
