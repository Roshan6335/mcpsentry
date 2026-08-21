import chalk from "chalk";
import { ScanReport } from "../scanner/staticScanner.js";
import { DriftResult } from "../utils/baseline.js";

const SEVERITY_COLOR: Record<string, (s: string) => string> = {
  critical: chalk.bgRed.white.bold,
  high: chalk.red.bold,
  medium: chalk.yellow.bold,
  low: chalk.gray,
};

export function printReport(report: ScanReport, drift?: DriftResult) {
  console.log();
  console.log(chalk.bold(`mcpsentry scan report`) + chalk.dim(`  —  ${report.serverCommand}`));
  console.log(chalk.dim(`${report.toolCount} tool(s) discovered · ${report.scannedAt}`));
  console.log();

  if (report.findings.length === 0) {
    console.log(chalk.green("✔ No known attack patterns detected in tool descriptions."));
  } else {
    console.log(chalk.bold(`Found ${report.findings.length} issue(s):\n`));
    for (const f of report.findings) {
      const badge = SEVERITY_COLOR[f.rule.severity](` ${f.rule.severity.toUpperCase()} `);
      console.log(`${badge}  ${chalk.bold(f.rule.id)}  ${chalk.cyan(f.toolName)}`);
      console.log(`   ${f.rule.description}`);
      console.log(`   ${chalk.dim(`"${f.snippet}"`)}`);
      console.log();
    }
  }

  if (drift) {
    if (!drift.hasBaseline) {
      console.log(chalk.dim("\nNo prior baseline found — this scan has been saved as the trust baseline."));
    } else if (drift.changedTools.length || drift.newTools.length || drift.removedTools.length) {
      console.log(chalk.bold.yellow("\n⚠ Drift detected since last approved scan:"));
      if (drift.changedTools.length)
        console.log(`  ${chalk.red("Changed:")} ${drift.changedTools.join(", ")} ${chalk.dim("(possible rug-pull — re-review before trusting)")}`);
      if (drift.newTools.length) console.log(`  ${chalk.yellow("New:")} ${drift.newTools.join(", ")}`);
      if (drift.removedTools.length) console.log(`  ${chalk.dim("Removed:")} ${drift.removedTools.join(", ")}`);
    } else {
      console.log(chalk.green("\n✔ No drift — tool definitions match the last approved baseline."));
    }
  }
  console.log();
}
