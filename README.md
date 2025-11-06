# AccuKnox Bifrost Plugin

A Bifrost plugin that integrates with AccuKnox LLM Defense API to scan prompts and responses for security threats and policy violations.

## Installation

### 1. Clone this Repository

```bash
git clone https://github.com/accuknox/bifrost-poc.git
cd accuknox-bifrost-plugin
```

### 2. Build the Plugin

```bash
make build
```

This creates `accuknox-plugin.so` - the compiled plugin file.

### 3. Get Bifrost HTTP Server

For testing, you'll need the `bifrost-http` binary. Get it from:
- **GitHub**: https://github.com/maximhq/bifrost
- Clone and build from `bifrost/transports/bifrost-http/`

Or use a pre-built binary if available.

## Configuration

### config.json

Create a `config.json` file with the following structure:

```json
{
  "log_level": "debug",
  "server": {
    "port": 8080,
    "host": "0.0.0.0"
  },
  "plugins": [
    {
      "enabled": true,
      "name": "accuknox-logger",
      "path": "./accuknox-plugin.so",
      "config": {
        "enabled": true,
        "api_key": "your-accuknox-jwt-token-here",
        "user_info": "your-email@example.com"
      }
    }
  ],
  "providers": {
    "openai": {
      "keys": [
        {
          "value": "sk-your-openai-api-key",
          "models": ["gpt-3.5-turbo", "gpt-4"],
          "weight": 1.0
        }
      ]
    }
  }
}
```

### Configuration Fields

#### Plugin Config

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `enabled` | boolean | Yes | Enable/disable the plugin |
| `api_key` | string | Yes | AccuKnox JWT token for API authentication |
| `user_info` | string | Yes | User email or identifier |

#### How JWT Token Works

The plugin automatically:
1. Decodes the JWT token (no signature verification)
2. Extracts the `iss` (issuer) field
3. Determines environment from issuer (e.g., `cspm.dev.accuknox.com` → `dev`)
4. Selects the correct API endpoint:
   - `dev` → `https://cwpp.dev.accuknox.com/llm-defence/application-query`
   - `stage` → `https://cwpp.stage.accuknox.com/llm-defence/application-query`
   - `demo` → `https://cwpp.demo.accuknox.com/llm-defence/application-query`
   - `prod` → `https://cwpp.prod.accuknox.com/llm-defence/application-query`

## Usage

### 1. Start Bifrost HTTP Server

For testing config use bifrost-http

```bash
./bifrost-http -app-dir . -log-level debug -log-style pretty
```

You should see:
```
[AccuKnox Plugin] Init called
[AccuKnox Plugin] Initialized with user_info: your-email@example.com
[AccuKnox Plugin] AccuKnox API client initialized: https://cwpp.dev.accuknox.com/llm-defence/application-query
```

### 2. Make API Requests

```bash
curl -X POST http://localhost:8080/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "openai/gpt-3.5-turbo",
    "messages": [
      {
        "role": "user",
        "content": "Hello, how are you?"
      }
    ],
    "max_tokens": 100
  }'
```

### 3. Monitor Logs

The plugin logs detailed information about each request:

**PreHook (Input):**
```
[AccuKnox Plugin] PreHook called
=================================================================================
[AccuKnox Plugin] REQUEST ID: 1e84d950-9def-4947-97e3-628e7c212ede
[AccuKnox Plugin] Provider: openai
[AccuKnox Plugin] Model: gpt-3.5-turbo
[AccuKnox Plugin] Request Type: chat_completion
[AccuKnox Plugin] Timestamp: 2025-11-06T12:51:31Z
[AccuKnox Plugin] INPUT PROMPT:
user: Hello, how are you?
=================================================================================
[AccuKnox Plugin] Prompt scanned successfully, session_id: f83711ca-f308-4618-baa3-21015bd993be
```

**PostHook (Output):**
```
[AccuKnox Plugin] PostHook called
=================================================================================
[AccuKnox Plugin] REQUEST ID: 1e84d950-9def-4947-97e3-628e7c212ede
[AccuKnox Plugin] Timestamp: 2025-11-06T12:51:33Z
[AccuKnox Plugin] OUTPUT RESPONSE:
Hello! I'm doing great, thank you for asking! How can I assist you today?
[AccuKnox Plugin] Token Usage - Prompt: 9, Completion: 9, Total: 18
[AccuKnox Plugin] Latency: 1083 ms
=================================================================================
[AccuKnox Plugin] Response scanned successfully
```