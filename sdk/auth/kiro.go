package auth

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/auth/kiro"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/browser"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/misc"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/util"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	log "github.com/sirupsen/logrus"
)

type KiroAuthenticator struct {
	CallbackPort int
}

func NewKiroAuthenticator() *KiroAuthenticator {
	return &KiroAuthenticator{CallbackPort: 19876}
}

func (a *KiroAuthenticator) Provider() string { return kiro.ProviderKey }

func (a *KiroAuthenticator) RefreshLead() *time.Duration { return new(5 * time.Minute) }

func (a *KiroAuthenticator) Login(ctx context.Context, cfg *config.Config, opts *LoginOptions) (*coreauth.Auth, error) {
	if cfg == nil {
		return nil, fmt.Errorf("cliproxy auth: configuration is required")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if opts == nil {
		opts = &LoginOptions{}
	}
	method := "google"
	region := kiro.DefaultRegion
	prefix := ""
	proxyURL := ""
	if opts.Metadata != nil {
		if v := strings.TrimSpace(opts.Metadata["auth-method"]); v != "" {
			method = v
		} else if v := strings.TrimSpace(opts.Metadata["method"]); v != "" {
			method = v
		}
		if v := strings.TrimSpace(opts.Metadata["region"]); v != "" {
			region = v
		}
		prefix = strings.TrimSpace(opts.Metadata["prefix"])
		proxyURL = strings.TrimSpace(opts.Metadata["proxy-url"])
	}
	idp, socialProvider, err := kiro.NormalizeSocialProvider(method)
	if err != nil {
		return nil, err
	}
	callbackPort := a.CallbackPort
	if opts.CallbackPort > 0 {
		callbackPort = opts.CallbackPort
	}
	pkce, err := kiro.GeneratePKCECodes()
	if err != nil {
		return nil, err
	}
	state, err := misc.GenerateRandomState()
	if err != nil {
		return nil, fmt.Errorf("kiro oauth: generate state: %w", err)
	}
	oauthServer := kiro.NewOAuthServer(callbackPort)
	if err = oauthServer.Start(); err != nil {
		return nil, fmt.Errorf("kiro oauth: start callback server: %w", err)
	}
	defer func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if stopErr := oauthServer.Stop(stopCtx); stopErr != nil {
			log.Warnf("kiro oauth server stop error: %v", stopErr)
		}
	}()
	redirectURI := oauthServer.RedirectURI()
	authURL, err := kiro.BuildAuthURL(region, idp, redirectURI, state, pkce)
	if err != nil {
		return nil, err
	}
	if !opts.NoBrowser {
		fmt.Println("Opening browser for Kiro authentication")
		if !browser.IsAvailable() {
			log.Warn("No browser available; please open the URL manually")
			util.PrintSSHTunnelInstructions(callbackPort)
			fmt.Printf("Visit the following URL to continue authentication:\n%s\n", authURL)
		} else if err = browser.OpenURL(authURL); err != nil {
			log.Warnf("Failed to open browser automatically: %v", err)
			util.PrintSSHTunnelInstructions(callbackPort)
			fmt.Printf("Visit the following URL to continue authentication:\n%s\n", authURL)
		}
	} else {
		util.PrintSSHTunnelInstructions(callbackPort)
		fmt.Printf("Visit the following URL to continue authentication:\n%s\n", authURL)
	}
	fmt.Println("Waiting for Kiro authentication callback...")
	result, err := oauthServer.WaitForCallback(10 * time.Minute)
	if err != nil {
		return nil, err
	}
	if result.Error != "" {
		return nil, fmt.Errorf("kiro oauth: callback error: %s", result.Error)
	}
	if result.State != state {
		return nil, fmt.Errorf("kiro oauth: state mismatch")
	}
	storage, err := kiro.ExchangeCode(ctx, cfg, proxyURL, region, result.Code, redirectURI, pkce, socialProvider)
	if err != nil {
		return nil, err
	}
	fileName := fmt.Sprintf("kiro-%s-%d.json", socialProvider, time.Now().Unix())
	metadata := map[string]any{
		"type":            kiro.ProviderKey,
		"auth_method":     "social",
		"social_provider": socialProvider,
		"region":          region,
	}
	if storage.ProfileARN != "" {
		metadata["profile_arn"] = storage.ProfileARN
	}
	fmt.Println("Kiro authentication successful")
	return &coreauth.Auth{
		ID:       fileName,
		Provider: kiro.ProviderKey,
		Prefix:   prefix,
		FileName: fileName,
		Storage:  storage,
		Metadata: metadata,
		Attributes: map[string]string{
			"auth_method":     "social",
			"social_provider": socialProvider,
			"region":          region,
		},
		Status: coreauth.StatusActive,
	}, nil
}
