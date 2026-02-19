/**
 * ClawGuard Plugin — OpenClaw DLP Bridge
 *
 * Hooks into `before_tool_call` to scan outbound content via the
 * ClawGuard Python service. Enforces BLOCK/REDACT decisions.
 */

interface PluginConfig {
  serviceUrl: string;
  blockOnError: boolean;
  timeoutMs: number;
}

interface ToolCallContext {
  toolName: string;
  args: Record<string, unknown>;
  agentId?: string;
  destination?: string;
}

interface ScanFinding {
  scanner_type: string;
  finding_type: string;
  severity: string;
  start: number;
  end: number;
  redacted_snippet?: string;
}

interface ScanResponse {
  action: "ALLOW" | "BLOCK" | "REDACT";
  content: string | null;
  findings: ScanFinding[];
  findings_count: number;
  scan_id: number | null;
  duration_ms: number;
}

interface HookResult {
  allow: boolean;
  modifiedArgs?: Record<string, unknown>;
  reason?: string;
}

const DEFAULT_CONFIG: PluginConfig = {
  serviceUrl: "http://127.0.0.1:8642",
  blockOnError: false,
  timeoutMs: 5000,
};

function extractContent(args: Record<string, unknown>): string {
  const parts: string[] = [];
  for (const [key, value] of Object.entries(args)) {
    if (typeof value === "string") {
      parts.push(value);
    } else if (value !== null && value !== undefined) {
      parts.push(JSON.stringify(value));
    }
  }
  return parts.join("\n");
}

function inferDestination(
  toolName: string,
  args: Record<string, unknown>
): string | undefined {
  // Try common arg names for URLs/hosts
  for (const key of ["url", "endpoint", "host", "destination", "to"]) {
    const val = args[key];
    if (typeof val === "string") {
      try {
        return new URL(val).hostname;
      } catch {
        return val;
      }
    }
  }
  return undefined;
}

async function scanContent(
  content: string,
  config: PluginConfig,
  context: ToolCallContext
): Promise<ScanResponse> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), config.timeoutMs);

  try {
    const resp = await fetch(`${config.serviceUrl}/api/v1/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        content,
        destination:
          context.destination ?? inferDestination(context.toolName, context.args),
        agent_id: context.agentId,
        tool_name: context.toolName,
      }),
      signal: controller.signal,
    });

    if (!resp.ok) {
      throw new Error(`ClawGuard returned ${resp.status}`);
    }

    return (await resp.json()) as ScanResponse;
  } finally {
    clearTimeout(timeout);
  }
}

/**
 * Main hook export — called by OpenClaw before each tool call.
 */
export async function beforeToolCall(
  context: ToolCallContext,
  pluginConfig?: Partial<PluginConfig>
): Promise<HookResult> {
  const config: PluginConfig = { ...DEFAULT_CONFIG, ...pluginConfig };

  const content = extractContent(context.args);
  if (!content.trim()) {
    return { allow: true };
  }

  let scan: ScanResponse;
  try {
    scan = await scanContent(content, config, context);
  } catch (err) {
    // Service unreachable — fail-open or fail-closed based on config
    if (config.blockOnError) {
      return {
        allow: false,
        reason: `ClawGuard service unreachable and blockOnError=true: ${err}`,
      };
    }
    return { allow: true };
  }

  switch (scan.action) {
    case "ALLOW":
      return { allow: true };

    case "BLOCK":
      return {
        allow: false,
        reason: `ClawGuard BLOCKED: ${scan.findings_count} finding(s) detected — ${scan.findings.map((f) => f.finding_type).join(", ")}`,
      };

    case "REDACT":
      if (scan.content !== null) {
        // Replace all string args with the redacted content
        // This is a simplified approach — a production version would
        // map redaction offsets back to individual args
        const modifiedArgs = { ...context.args };
        for (const key of Object.keys(modifiedArgs)) {
          if (typeof modifiedArgs[key] === "string") {
            modifiedArgs[key] = scan.content;
            break; // Only replace the first string arg for now
          }
        }
        return { allow: true, modifiedArgs };
      }
      return { allow: true };

    default:
      return { allow: true };
  }
}
