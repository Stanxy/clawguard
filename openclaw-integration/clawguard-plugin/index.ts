/**
 * ClawGuard Plugin — OpenClaw DLP Bridge
 *
 * Hooks into `before_tool_call` to scan outbound content via the
 * ClawGuard Python service. Enforces BLOCK/REDACT decisions.
 */

interface OpenClawPluginApi {
  id: string;
  name: string;
  pluginConfig?: Record<string, unknown>;
  on(hookName: string, handler: (...args: any[]) => any, opts?: { priority?: number }): void;
  [key: string]: any;
}

interface PluginConfig {
  serviceUrl: string;
  blockOnError: boolean;
  timeoutMs: number;
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
  action: "ALLOW" | "BLOCK" | "REDACT" | "PROMPT";
  content: string | null;
  findings: ScanFinding[];
  findings_count: number;
  scan_id: number | null;
  duration_ms: number;
  suggested_action: "ALLOW" | "BLOCK" | "REDACT" | null;
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
  context: { toolName: string; args: Record<string, unknown>; agentId?: string }
): Promise<ScanResponse> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), config.timeoutMs);

  try {
    const resp = await fetch(`${config.serviceUrl}/api/v1/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        content,
        destination: inferDestination(context.toolName, context.args),
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

async function promptUser(scan: ScanResponse): Promise<boolean> {
  // Fall back to auto-deny if stdin is not a TTY
  if (!process.stdin.isTTY) {
    return false;
  }

  const readline = await import("readline");
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stderr,
  });

  console.error(
    `\n[ClawGuard] ${scan.findings_count} finding(s) detected:`
  );
  for (const f of scan.findings) {
    console.error(
      `  - ${f.finding_type} (${f.severity})${f.redacted_snippet ? ": " + f.redacted_snippet : ""}`
    );
  }
  if (scan.suggested_action) {
    console.error(`  Suggested action: ${scan.suggested_action}`);
  }

  return new Promise<boolean>((resolve) => {
    rl.question("[ClawGuard] Allow this tool call? [y/N] ", (answer) => {
      rl.close();
      resolve(answer.trim().toLowerCase() === "y");
    });
  });
}

const plugin = {
  id: "clawwall",
  name: "ClawGuard",
  description:
    "DLP Surveillance Layer — scans outbound content for secrets, PII, and policy violations",
  configSchema: {
    type: "object" as const,
    additionalProperties: false,
    properties: {
      serviceUrl: {
        type: "string",
        default: "http://127.0.0.1:8642",
        description: "ClawGuard service URL",
      },
      blockOnError: {
        type: "boolean",
        default: false,
        description:
          "If true, block tool calls when the ClawGuard service is unreachable (fail-closed). Default: fail-open.",
      },
      timeoutMs: {
        type: "number",
        default: 5000,
        description: "Timeout for scan requests in milliseconds",
      },
    },
  },

  register(api: OpenClawPluginApi) {
    const pluginCfg = (api.pluginConfig ?? {}) as Partial<PluginConfig>;
    const config: PluginConfig = { ...DEFAULT_CONFIG, ...pluginCfg };

    api.on("before_tool_call", async (event: any, ctx: any) => {
      const content = extractContent(event.params);
      if (!content.trim()) {
        return;
      }

      let scan: ScanResponse;
      try {
        scan = await scanContent(content, config, {
          toolName: event.toolName,
          args: event.params,
          agentId: ctx.agentId,
        });
      } catch (err) {
        if (config.blockOnError) {
          return {
            block: true,
            blockReason: `ClawGuard service unreachable and blockOnError=true: ${err}`,
          };
        }
        return;
      }

      switch (scan.action) {
        case "ALLOW":
          return;

        case "BLOCK":
          return {
            block: true,
            blockReason: `ClawGuard BLOCKED: ${scan.findings_count} finding(s) detected — ${scan.findings.map((f) => f.finding_type).join(", ")}`,
          };

        case "REDACT":
          if (scan.content !== null) {
            const modifiedParams = { ...event.params };
            for (const key of Object.keys(modifiedParams)) {
              if (typeof modifiedParams[key] === "string") {
                modifiedParams[key] = scan.content;
                break;
              }
            }
            return { params: modifiedParams };
          }
          return;

        case "PROMPT": {
          const approved = await promptUser(scan);
          if (!approved) {
            return {
              block: true,
              blockReason: `ClawGuard BLOCKED (user denied): ${scan.findings_count} finding(s) — ${scan.findings.map((f) => f.finding_type).join(", ")}`,
            };
          }
          // User approved — apply redaction if suggested action was REDACT
          if (scan.suggested_action === "REDACT" && scan.content !== null) {
            const modifiedParams = { ...event.params };
            for (const key of Object.keys(modifiedParams)) {
              if (typeof modifiedParams[key] === "string") {
                modifiedParams[key] = scan.content;
                break;
              }
            }
            return { params: modifiedParams };
          }
          return;
        }

        default:
          return;
      }
    });
  },
};

export default plugin;
