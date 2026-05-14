# CLIProxyAPI Kiro OAuth reverse proxy plan

Session-derived planning reference for implementing AIClient2API-style `claude-kiro-oauth` in CLIProxyAPI.

## Goal

Add Kiro Google/GitHub OAuth login and reverse proxy access to Kiro backend Claude models in `ztp559/CLIProxyAPI`, using `ztp559/AIClient2API` as the source of truth for behavior.

## Key AIClient2API source files

```text
src/auth/kiro-oauth.js
src/providers/claude/claude-kiro.js
src/scripts/kiro-token-refresh.js
src/scripts/kiro-idc-token-refresh.js
```

## Kiro endpoints and OAuth details

Social login endpoints:

```text
https://prod.us-east-1.auth.desktop.kiro.dev/login
https://prod.us-east-1.auth.desktop.kiro.dev/oauth/token
https://prod.<region>.auth.desktop.kiro.dev/refreshToken
```

Backend model endpoint:

```text
https://q.<region>.amazonaws.com/generateAssistantResponse
```

Social OAuth behavior:

```text
idp=Google or idp=Github
redirect_uri=http://127.0.0.1:<port>/oauth/callback
callback ports: 19876-19880
PKCE: S256 code_challenge
state: required
prompt=select_account
```

Social token shape from AIClient2API:

```json
{
  "accessToken": "...",
  "refreshToken": "...",
  "profileArn": "...",
  "expiresAt": "2026-...Z",
  "authMethod": "social",
  "region": "us-east-1"
}
```

## Kiro request headers to preserve

AIClient2API uses these when calling `generateAssistantResponse`:

```text
Authorization: Bearer <accessToken>
Content-Type: application/json
Accept: application/json
amz-sdk-invocation-id: <uuid>
amz-sdk-request: attempt=1; max=3
x-amzn-codewhisperer-optout: true
x-amzn-kiro-agent-mode: vibe
x-amz-user-agent: aws-sdk-js/1.0.34 KiroIDE-<version>-<machineId>
user-agent: aws-sdk-js/1.0.34 ua/2.1 os/<os>#<release> lang/js md/nodejs#<nodeVersion> api/codewhispererstreaming#1.0.34 m/E KiroIDE-<version>-<machineId>
```

Current Kiro version observed in AIClient2API:

```text
0.11.63
```

Machine ID logic:

```text
SHA256(uuid || profileArn || clientId || "KIRO_DEFAULT_MACHINE")
```

## CLIProxyAPI implementation shape

Canonical provider key:

```text
kiro
```

Compatibility aliases:

```text
claude-kiro-oauth
kiro-oauth
```

Suggested auth record mapping:

```json
{
  "provider": "kiro",
  "attributes": {
    "auth_method": "social",
    "social_provider": "Google|Github",
    "region": "us-east-1",
    "profile_arn": "...",
    "machine_id": "..."
  },
  "metadata": {
    "access_token": "...",
    "refresh_token": "...",
    "expires_at": "2026-...Z"
  }
}
```

Likely CLIProxyAPI files/directories:

```text
internal/auth/kiro/                 # new OAuth + token refresh package
sdk/auth/kiro.go                    # if auth registry needs SDK wrapper
internal/runtime/executor/kiro_*.go # new executor/request/response/stream code
sdk/cliproxy/service.go             # register executor and aliases
config.example.yaml                 # config docs/example
provider/model registry files       # expose Kiro Claude models
management/CLI auth routing files   # login provider support
```

## PR breakdown

1. **PR 1 — OAuth + refresh foundation**
   - Add Kiro OAuth package.
   - Add Google/GitHub social login.
   - Add refreshToken integration.
   - Add provider alias handling and docs.

2. **PR 2 — non-stream Claude Messages executor**
   - Add `NewKiroExecutor`.
   - Support Claude `/v1/messages` non-stream first.
   - Build Kiro `generateAssistantResponse` payload.
   - Parse Kiro response into Claude-compatible response.

3. **PR 3 — OpenAI compatibility + tools + models**
   - Support `/v1/chat/completions` through existing translator path where possible.
   - Add tool definitions/tool_use/tool_result conversion.
   - Implement long tool-name shortening/restoration (Kiro max 64 chars).
   - Register model list/aliases.

4. **PR 4 — streaming + robustness**
   - Add `ExecuteStream`.
   - Preserve thinking/tool event boundaries.
   - Handle cancellation, usage, quota/cooldown/failover.

## Model mapping from AIClient2API

```text
claude-haiku-4-5               -> claude-haiku-4.5
claude-opus-4-7                -> claude-opus-4.7
claude-opus-4-6                -> claude-opus-4.6
claude-opus-4-5                -> claude-opus-4.5
claude-opus-4-5-20251101       -> claude-opus-4.5
claude-sonnet-4-6              -> claude-sonnet-4.6
claude-sonnet-4-5              -> claude-sonnet-4.5
claude-sonnet-4-5-20250929     -> claude-sonnet-4.5
```

Context estimates from AIClient2API:

```text
Sonnet/Haiku: 200K
Opus variants: 1M
```

Thinking budget behavior:

```text
min: 1024
max: 24576
default: 20000
```

## Validation checklist

```bash
gofmt -w internal/auth/kiro internal/runtime/executor sdk/auth sdk/cliproxy

go test ./internal/auth/kiro ./internal/runtime/executor ./sdk/auth ./sdk/cliproxy

go test ./...

go build -o test-output ./cmd/server && rm test-output
```

Manual OAuth smoke tests:

```bash
cli-proxy-api --config config.yaml --login --provider kiro --auth-method google --oauth-callback-port 19876
cli-proxy-api --config config.yaml --login --provider kiro --auth-method github --oauth-callback-port 19876
```

Claude-compatible smoke request:

```bash
curl http://localhost:8317/v1/messages \
  -H 'Authorization: Bearer <api-key>' \
  -H 'Content-Type: application/json' \
  -d '{
    "model": "claude-sonnet-4-5",
    "max_tokens": 256,
    "messages": [{"role": "user", "content": "Reply with OK"}]
  }'
```

## Pitfalls

- Do not implement all protocols and streaming in the first PR; start with OAuth + non-stream Claude Messages.
- Do not bind OAuth callback servers to non-localhost.
- Do not log callback URLs with `code`/`state`, token JSON, or Authorization headers.
- CLIProxyAPI repository convention allows timeouts for credential acquisition but not for long-running upstream network behavior after connection is established.
- Keep Kiro request/response schema isolated in dedicated files because Kiro backend schema may drift.
