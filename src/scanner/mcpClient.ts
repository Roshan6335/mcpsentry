import { spawn, ChildProcessWithoutNullStreams } from "node:child_process";
import { randomUUID } from "node:crypto";

export interface McpTool {
  name: string;
  description?: string;
  inputSchema?: unknown;
}

interface JsonRpcResponse {
  jsonrpc: "2.0";
  id?: string | number;
  result?: any;
  error?: { code: number; message: string };
}

/**
 * Spawns an MCP server process, performs the initialize handshake,
 * and requests its tool list. This mirrors exactly what a real MCP
 * client (Claude Code, Cursor, etc.) does on first connection — which
 * is precisely the moment tool-poisoning payloads get delivered.
 */
export class McpStdioClient {
  private proc: ChildProcessWithoutNullStreams;
  private buffer = "";
  private pending = new Map<string, (res: JsonRpcResponse) => void>();

  constructor(command: string, args: string[] = []) {
    this.proc = spawn(command, args, { stdio: ["pipe", "pipe", "pipe"] });

    this.proc.stdout.on("data", (chunk: Buffer) => {
      this.buffer += chunk.toString();
      this.drainBuffer();
    });
  }

  private drainBuffer() {
    // MCP stdio transport is newline-delimited JSON-RPC messages
    let idx: number;
    while ((idx = this.buffer.indexOf("\n")) !== -1) {
      const line = this.buffer.slice(0, idx).trim();
      this.buffer = this.buffer.slice(idx + 1);
      if (!line) continue;
      try {
        const msg = JSON.parse(line) as JsonRpcResponse;
        if (msg.id !== undefined && this.pending.has(String(msg.id))) {
          this.pending.get(String(msg.id))!(msg);
          this.pending.delete(String(msg.id));
        }
      } catch {
        // not a JSON line (some servers log to stdout) — ignore for MVP
      }
    }
  }

  private send(method: string, params: unknown = {}, expectResponse = true): Promise<JsonRpcResponse> {
    const id = randomUUID();
    const payload = { jsonrpc: "2.0", id, method, params };
    return new Promise((resolve, reject) => {
      if (expectResponse) {
        const timeout = setTimeout(() => {
          this.pending.delete(id);
          reject(new Error(`Timed out waiting for response to ${method}`));
        }, 8000);
        this.pending.set(id, (res) => {
          clearTimeout(timeout);
          resolve(res);
        });
      }
      this.proc.stdin.write(JSON.stringify(payload) + "\n");
      if (!expectResponse) resolve({ jsonrpc: "2.0" });
    });
  }

  private notify(method: string, params: unknown = {}) {
    const payload = { jsonrpc: "2.0", method, params };
    this.proc.stdin.write(JSON.stringify(payload) + "\n");
  }

  async listTools(): Promise<McpTool[]> {
    await this.send("initialize", {
      protocolVersion: "2025-06-18",
      capabilities: {},
      clientInfo: { name: "mcp-guard-scanner", version: "0.1.0" },
    });
    this.notify("notifications/initialized");

    const res = await this.send("tools/list", {});
    if (res.error) throw new Error(`Server error: ${res.error.message}`);
    return (res.result?.tools ?? []) as McpTool[];
  }

  close() {
    this.proc.stdin.end();
    this.proc.kill();
  }
}
