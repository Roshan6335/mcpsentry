import { spawn } from "node:child_process";
import { scanText } from "../rules/patterns.js";
import { appendFile } from "node:fs/promises";
import { join } from "node:path";
import { homedir } from "node:os";

const LOG_FILE = join(homedir(), ".mcp-guard", "proxy.log");

async function log(entry: Record<string, unknown>) {
  try {
    await appendFile(LOG_FILE, JSON.stringify({ ts: new Date().toISOString(), ...entry }) + "\n");
  } catch {
    // best-effort logging only, never crash the proxy over a log write
  }
}

interface ProxyOptions {
  /** the REAL mcp server command that this proxy wraps */
  targetCommand: string;
  targetArgs: string[];
  /** block responses that trip a "critical" rule instead of just warning */
  blockCritical: boolean;
}

/**
 * mcp-guard runs itself as the MCP server your client connects to.
 * It transparently forwards everything to the real server underneath,
 * except: every `tools/call` RESULT is scanned before being relayed
 * back to the client. This is the runtime channel that connect-time-only
 * scanners (and MCP itself) leave completely unchecked.
 *
 *   Claude Code  <--stdio-->  mcp-guard proxy  <--stdio-->  real MCP server
 */
export function startProxy({ targetCommand, targetArgs, blockCritical }: ProxyOptions) {
  const target = spawn(targetCommand, targetArgs, { stdio: ["pipe", "pipe", "pipe"] });

  let clientBuffer = "";
  let targetBuffer = "";

  // Track outstanding tools/call requests by id so we know which
  // responses are tool-call RESULTS (the highest-risk payloads) vs
  // ordinary protocol chatter (initialize, tools/list, etc.)
  const pendingToolCalls = new Set<string>();

  // ---- client -> proxy -> target (requests) ----
  process.stdin.on("data", (chunk: Buffer) => {
    clientBuffer += chunk.toString();
    let idx: number;
    while ((idx = clientBuffer.indexOf("\n")) !== -1) {
      const line = clientBuffer.slice(0, idx).trim();
      clientBuffer = clientBuffer.slice(idx + 1);
      if (!line) continue;

      try {
        const msg = JSON.parse(line);
        if (msg.method === "tools/call" && msg.id !== undefined) {
          pendingToolCalls.add(String(msg.id));
        }
      } catch {
        // pass through unparsed lines as-is
      }

      target.stdin.write(line + "\n");
    }
  });

  // ---- target -> proxy -> client (responses) ----
  target.stdout.on("data", (chunk: Buffer) => {
    targetBuffer += chunk.toString();
    let idx: number;
    while ((idx = targetBuffer.indexOf("\n")) !== -1) {
      const line = targetBuffer.slice(0, idx).trim();
      targetBuffer = targetBuffer.slice(idx + 1);
      if (!line) continue;

      let forward = line;

      try {
        const msg = JSON.parse(line);
        const isToolCallResult = msg.id !== undefined && pendingToolCalls.has(String(msg.id));

        if (isToolCallResult) {
          pendingToolCalls.delete(String(msg.id));
          const resultText = JSON.stringify(msg.result ?? {});
          const hits = scanText(resultText);

          if (hits.length > 0) {
            log({ event: "runtime_finding", ruleIds: hits.map((h) => h.rule.id), preview: resultText.slice(0, 300) });

            const hasCritical = hits.some((h) => h.rule.severity === "critical");
            if (hasCritical && blockCritical) {
              // Replace the tool result with a blocked-content notice instead
              // of relaying the raw (potentially malicious) payload to the LLM.
              const blocked = {
                jsonrpc: "2.0",
                id: msg.id,
                result: {
                  content: [
                    {
                      type: "text",
                      text: `[mcp-guard] Blocked: this tool response tripped ${hits
                        .map((h) => h.rule.id)
                        .join(", ")} (possible prompt injection / tool poisoning). Run 'mcp-guard scan' for details.`,
                    },
                  ],
                  isError: true,
                },
              };
              forward = JSON.stringify(blocked);
              process.stderr.write(
                `\n[mcp-guard] 🚫 BLOCKED a tool response (rules: ${hits.map((h) => h.rule.id).join(", ")})\n`
              );
            } else {
              process.stderr.write(
                `\n[mcp-guard] ⚠️  Suspicious tool response allowed through (rules: ${hits
                  .map((h) => h.rule.id)
                  .join(", ")}) — re-run with --block-critical to enforce\n`
              );
            }
          }
        }
      } catch {
        // not JSON — forward untouched
      }

      process.stdout.write(forward + "\n");
    }
  });

  target.stderr.on("data", (chunk: Buffer) => process.stderr.write(chunk));
  process.on("exit", () => target.kill());
  target.on("exit", (code) => process.exit(code ?? 0));
}
