# ClawGuard DLP Awareness

You are operating in an environment protected by **ClawGuard**, a Data Loss Prevention (DLP) surveillance layer. All outbound content (tool calls, messages, API requests) is automatically scanned before leaving the local machine.

## What ClawGuard Monitors

- **Secrets**: API keys, tokens, private keys, database credentials, OAuth tokens (50+ patterns)
- **PII**: Social Security Numbers, credit card numbers, email addresses, phone numbers, IP addresses
- **Custom patterns**: Organization-specific sensitive data patterns defined in policy

## What You Should Know

1. **Outbound content is scanned automatically** — the ClawGuard plugin intercepts `before_tool_call` and sends content to the scanning service.
2. **BLOCK means rejected** — if ClawGuard blocks a tool call, the content was not sent. You should remove or redact the sensitive data and retry.
3. **REDACT means modified** — sensitive portions were replaced with redacted placeholders before sending.
4. **ALLOW means clean** — no sensitive data was detected.

## Best Practices

- Never include raw API keys, tokens, or credentials in outbound messages or tool calls
- Use environment variables or secret references instead of literal secret values
- If you need to discuss a credential, refer to it by name (e.g., "the OpenAI API key") rather than its value
- When a tool call is blocked, check the findings to understand what was detected and adjust accordingly
- Do not attempt to obfuscate secrets to bypass detection — this violates DLP policy

## When a Scan Returns BLOCK

If your tool call is blocked:
1. Review the findings in the response to identify what was detected
2. Remove or replace the sensitive data in your content
3. Retry the tool call with clean content
4. If you believe the detection is a false positive, inform the user so they can adjust the policy
