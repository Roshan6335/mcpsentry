import { readFile, writeFile, mkdir } from "node:fs/promises";
import { existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { homedir } from "node:os";

const BASELINE_DIR = join(homedir(), ".mcp-guard");
const BASELINE_FILE = join(BASELINE_DIR, "baseline.json");

export interface BaselineStore {
  [serverCommand: string]: {
    toolHashes: Record<string, string>;
    savedAt: string;
  };
}

async function ensureDir() {
  if (!existsSync(BASELINE_DIR)) {
    await mkdir(BASELINE_DIR, { recursive: true });
  }
}

export async function loadBaseline(): Promise<BaselineStore> {
  if (!existsSync(BASELINE_FILE)) return {};
  const raw = await readFile(BASELINE_FILE, "utf-8");
  try {
    return JSON.parse(raw) as BaselineStore;
  } catch {
    return {};
  }
}

export async function saveBaselineFor(serverCommand: string, toolHashes: Record<string, string>) {
  await ensureDir();
  const store = await loadBaseline();
  store[serverCommand] = { toolHashes, savedAt: new Date().toISOString() };
  await writeFile(BASELINE_FILE, JSON.stringify(store, null, 2), "utf-8");
}

export interface DriftResult {
  hasBaseline: boolean;
  changedTools: string[];
  newTools: string[];
  removedTools: string[];
}

export async function checkDrift(serverCommand: string, currentHashes: Record<string, string>): Promise<DriftResult> {
  const store = await loadBaseline();
  const prior = store[serverCommand];

  if (!prior) {
    return { hasBaseline: false, changedTools: [], newTools: [], removedTools: [] };
  }

  const changedTools: string[] = [];
  const newTools: string[] = [];
  const removedTools: string[] = [];

  for (const [name, hash] of Object.entries(currentHashes)) {
    if (!(name in prior.toolHashes)) newTools.push(name);
    else if (prior.toolHashes[name] !== hash) changedTools.push(name);
  }
  for (const name of Object.keys(prior.toolHashes)) {
    if (!(name in currentHashes)) removedTools.push(name);
  }

  return { hasBaseline: true, changedTools, newTools, removedTools };
}
