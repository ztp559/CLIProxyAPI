package cmd

import (
	"context"
	"fmt"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	sdkAuth "github.com/router-for-me/CLIProxyAPI/v7/sdk/auth"
)

// DoKiroLogin triggers the Kiro OAuth flow through the shared authentication manager.
// It initiates the OAuth authentication process for Kiro (AWS-based Claude access)
// and saves the authentication tokens to the configured auth directory.
//
// Parameters:
//   - cfg: The application configuration
//   - options: Login options including browser behavior, callback port, and auth method
func DoKiroLogin(cfg *config.Config, options *LoginOptions) {
	if options == nil {
		options = &LoginOptions{}
	}

	promptFn := options.Prompt
	if promptFn == nil {
		promptFn = defaultProjectPrompt()
	}

	manager := newAuthManager()

	metadata := map[string]string{}
	if options.AuthMethod != "" {
		metadata["auth-method"] = options.AuthMethod
	}
	if options.Region != "" {
		metadata["region"] = options.Region
	}

	authOpts := &sdkAuth.LoginOptions{
		NoBrowser:    options.NoBrowser,
		CallbackPort: options.CallbackPort,
		Metadata:     metadata,
		Prompt:       promptFn,
	}

	_, savedPath, err := manager.Login(context.Background(), "kiro", cfg, authOpts)
	if err != nil {
		fmt.Printf("Kiro authentication failed: %v\n", err)
		return
	}

	if savedPath != "" {
		fmt.Printf("Authentication saved to %s\n", savedPath)
	}
	fmt.Println("Kiro authentication successful!")
}
