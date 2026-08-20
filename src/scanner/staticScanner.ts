import { McpStdioClient, McpTool } from "./mcpClient.js";
import { scanText, Rule } from "../rules/patterns.js";

export interface ToolFinding {
  toolName: string;
  rule: Rule;
  snippet: string;
}

export interface ScanReport {
  serverCommand: string;
  toolCount: number;
  findings: ToolFinding[];
  toolHashes: Record<string, string>; // for drift detection baseline
  scannedAt: string;
}

function snippetAround(text: string, max = 120): string {
  return text.length > max ? text.slice(0, max) + "…" : text;
}

async function hashString(input: string): Promise<string> {
  const { createHash } = await import("node:crypto");
  return createHash("sha256").update(input).digest("hex");
}

export async function scanServer(command: string, args: string[] = []): Promise<ScanReport> {
  const client = new McpStdioClient(command, args);
  let tools: McpTool[] = [];
  try {
    tools = await client.listTools();
  } finally {
    client.close();
  }

  const findings: ToolFinding[] = [];
  const toolHashes: Record<string, string> = {};

  for (const tool of tools) {
    const text = `${tool.name}\n${tool.description ?? ""}\n${JSON.stringify(tool.inputSchema ?? {})}`;
    toolHashes[tool.name] = await hashString(text);

    const hits = scanText(text);
    for (const { rule } of hits) {
      findings.push({
        toolName: tool.name,
        rule,
        snippet: snippetAround(tool.description ?? tool.name),
      });
    }
  }

  return {
    serverCommand: `${command} ${args.join(" ")}`.trim(),
    toolCount: tools.length,
    findings,
    toolHashes,
    scannedAt: new Date().toISOString(),
  };
}
