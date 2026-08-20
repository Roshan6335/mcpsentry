#!/usr/bin/env node
import { Command } from "commander";
import chalk from "chalk";
import { scanServer } from "./scanner/staticScanner.js";
import { loadBaseline, saveBaselineFor, checkDrift } from "./utils/baseline.js";
import { printReport } from "./utils/report.js";
import { startProxy } from "./proxy/proxy.js";

const program = new Command();

program
  .name("mcp-guard")
  .description("Security scanner + runtime proxy for MCP servers")
  .version("0.1.0");

program
  .command("scan")
  .description("Statically scan an MCP server's tool descriptions for known attack patterns")
  .argument("<command>", "the command used to launch the MCP server, e.g. \"npx\"")
  .argument("[args...]", "arguments to that command, e.g. \"-y @some/mcp-server\"")
  .option("--save-baseline", "save this scan's tool hashes as the trusted baseline for drift detection", false)
  .action(async (command: string, args: string[], opts: { saveBaseline: boolean }) => {
    console.log(chalk.dim(`Connecting to MCP server: ${command} ${args.join(" ")} ...`));
    try {
      const report = await scanServer(command, args);
      const drift = await checkDrift(report.serverCommand, report.toolHashes);
      printReport(report, drift);

      if (opts.saveBaseline || !drift.hasBaseline) {
        await saveBaselineFor(report.serverCommand, report.toolHashes);
      }

      const hasCritical = report.findings.some((f) => f.rule.severity === "critical");
      process.exit(hasCritical ? 1 : 0);
    } catch (err) {
      console.error(chalk.red(`Scan failed: ${(err as Error).message}`));
      process.exit(2);
    }
  });

program
  .command("proxy")
  .description("Run mcp-guard as a transparent runtime proxy in front of a real MCP server")
  .argument("<command>", "the real MCP server command")
  .argument("[args...]", "arguments to that command")
  .option("--block-critical", "block tool responses that trip a CRITICAL rule instead of just warning", false)
  .action((command: string, args: string[], opts: { blockCritical: boolean }) => {
    process.stderr.write(chalk.dim(`[mcp-guard] proxying ${command} ${args.join(" ")}\n`));
    startProxy({ targetCommand: command, targetArgs: args, blockCritical: opts.blockCritical });
  });

program
  .command("baseline")
  .description("List servers with a saved trust baseline")
  .action(async () => {
    const store = await loadBaseline();
    const entries = Object.entries(store);
    if (entries.length === 0) {
      console.log(chalk.dim("No baselines saved yet. Run `mcp-guard scan --save-baseline <cmd>` first."));
      return;
    }
    for (const [cmd, data] of entries) {
      console.log(`${chalk.cyan(cmd)}  ${chalk.dim(`(${Object.keys(data.toolHashes).length} tools, saved ${data.savedAt})`)}`);
    }
  });

program.parse();
