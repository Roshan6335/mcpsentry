/**
 * mcp-guard detection rules
 *
 * These are heuristic signatures for known MCP attack classes:
 *  - Tool Poisoning (malicious instructions hidden in tool descriptions)
 *  - Indirect Prompt Injection (instructions smuggled inside tool *responses*)
 *  - Rug Pulls (silent redefinition of a previously-trusted tool)
 *  - Excessive scope requests (asking for far more access than the tool needs)
 *
 * This list is intentionally simple regex/heuristic matching for the MVP.
 * In the SaaS version this becomes a maintained, versioned, community-fed
 * threat-intel database (think: Snyk vulnerability DB, but for MCP servers).
 */

export interface Rule {
  id: string;
  description: string;
  severity: "low" | "medium" | "high" | "critical";
  category: "tool-poisoning" | "prompt-injection" | "excessive-scope" | "obfuscation" | "credential-exposure";
  test: (text: string) => boolean;
}

const IMPERATIVE_OVERRIDE_PHRASES = [
  /ignore (all|any|the)?\s*(previous|prior|above)\s*(instructions|prompts|rules)/i,
  /disregard (all|any|the)?\s*(previous|prior|above)/i,
  /you must (now|always|immediately)/i,
  /do not (tell|inform|notify|show) the user/i,
  /without (asking|confirming|telling) the user/i,
  /system\s*:\s*override/i,
  /new instructions?:/i,
  /\[?system prompt\]?/i,
  /act as (if you are|the) (system|admin|root)/i,
];

const DATA_EXFIL_PATTERNS = [
  /send.{0,30}(to|via).{0,30}(http|url|webhook|email)/i,
  /post.{0,20}(data|contents|file|result).{0,20}to/i,
  /include.{0,20}(api[_ ]?key|token|secret|credential)/i,
  /upload.{0,20}(all|entire|full).{0,20}(file|data|table|database)/i,
];

const OBFUSCATION_INDICATORS = [
  /[\u200B-\u200F\uFEFF\u2060-\u2064]/, // zero-width / invisible unicode
  /&#x?[0-9a-f]+;/i, // HTML entity encoding used to hide text
  /(?:[A-Za-z0-9+/]{40,}={0,2})/, // long base64-looking blobs
];

const EXCESSIVE_SCOPE_KEYWORDS = [
  /full (file ?system|disk) access/i,
  /unrestricted network access/i,
  /read (and|\/)? write (all|any) files/i,
  /execute arbitrary (shell|code|commands?)/i,
];

export const RULES: Rule[] = [
  {
    id: "MCP-001",
    description: "Tool description contains an instruction-override phrase typical of tool poisoning",
    severity: "critical",
    category: "tool-poisoning",
    test: (text) => IMPERATIVE_OVERRIDE_PHRASES.some((r) => r.test(text)),
  },
  {
    id: "MCP-002",
    description: "Content suggests exfiltrating data to an external endpoint",
    severity: "critical",
    category: "prompt-injection",
    test: (text) => DATA_EXFIL_PATTERNS.some((r) => r.test(text)),
  },
  {
    id: "MCP-003",
    description: "Hidden/invisible characters or encoded blobs detected — classic obfuscation technique",
    severity: "high",
    category: "obfuscation",
    test: (text) => OBFUSCATION_INDICATORS.some((r) => r.test(text)),
  },
  {
    id: "MCP-004",
    description: "Tool requests unusually broad permissions relative to its stated purpose",
    severity: "medium",
    category: "excessive-scope",
    test: (text) => EXCESSIVE_SCOPE_KEYWORDS.some((r) => r.test(text)),
  },
  {
    id: "MCP-005",
    description: "Description references credentials, tokens, or secrets in a way that looks like harvesting rather than usage",
    severity: "high",
    category: "credential-exposure",
    test: (text) => /(api[_ ]?key|access[_ ]?token|secret)s?\s*(here|below|:|=)/i.test(text) && /(send|post|forward|log|print)/i.test(text),
  },
  {
    id: "MCP-006",
    description: "Suspiciously long or nested description — often used to bury injected instructions in noise",
    severity: "low",
    category: "tool-poisoning",
    test: (text) => text.length > 1500,
  },
];

export function scanText(text: string): { rule: Rule }[] {
  return RULES.filter((rule) => rule.test(text)).map((rule) => ({ rule }));
}
