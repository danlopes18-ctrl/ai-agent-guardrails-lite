#!/usr/bin/env node
/**
 * CLI #06 — Zero-Dependency OWASP PR & File Security Auditor
 * Scans a git diff (--staged / --base main) OR a directory (--dir path) against
 * 14 high-signal vulnerability & secret rules, outputting JSON or Markdown PR report.
 */
import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { scanTextForSecrets } from "../hooks/_lib/patterns.mjs";

const CODE_RULES = [
  { id: "EVAL_DYNAMIC", severity: "HIGH", msg: "Dynamic eval()/new Function() execution", regex: /\b(?:eval|Function)\s*\(/g },
  { id: "CHILD_PROCESS_EXEC_INTERP", severity: "CRITICAL", msg: "Shell command string interpolation in exec/execSync (use execFileSync)", regex: /\bexec(?:Sync)?\s*\(\s*`[^`]*\$\{/g },
  { id: "SQL_STRING_INTERP", severity: "CRITICAL", msg: "Possible SQL injection via template literal interpolation", regex: /(?:SELECT|INSERT|UPDATE|DELETE)\b[^`\n]{0,80}\$\{/gi },
  { id: "DANGEROUS_INNER_HTML", severity: "HIGH", msg: "Raw HTML injection sink (dangerouslySetInnerHTML / innerHTML)", regex: /(?:dangerouslySetInnerHTML|\.innerHTML\s*=)/g },
  { id: "TLS_VERIFY_DISABLED", severity: "CRITICAL", msg: "TLS certificate verification disabled (rejectUnauthorized: false)", regex: /rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0/g },
  { id: "CORS_WILDCARD_CREDS", severity: "HIGH", msg: "Permissive CORS wildcard with credentials", regex: /Access-Control-Allow-Origin['"\s:]+\*/gi },
  { id: "WEAK_HASH_AUTH", severity: "MEDIUM", msg: "Weak hash algorithm (MD5/SHA1) — do not use for passwords/tokens", regex: /createHash\s*\(\s*['"](?:md5|sha1)['"]\s*\)/gi },
  { id: "HARDCODED_JWT_SECRET", severity: "CRITICAL", msg: "Hardcoded JWT secret fallback", regex: /jwt\.sign\s*\([^)]*['"][^'"]{4,}['"]/g },
  { id: "MATH_RANDOM_TOKEN", severity: "MEDIUM", msg: "Non-cryptographic Math.random() near token/id/secret logic", regex: /(?:token|secret|nonce|otp|key)[^\n]{0,40}Math\.random\s*\(/gi },
  { id: "OPEN_REDIRECT", severity: "MEDIUM", msg: "Unvalidated redirect directly from user query/body", regex: /res\.redirect\s*\(\s*req\.(?:query|body|params)/g }
];

const SKIP_DIRS = new Set([".git", "node_modules", "dist", "build", ".next", "coverage"]);
const SCAN_EXTS = new Set([".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".py", ".go", ".sql", ".env", ".yml", ".yaml", ".json"]);

function scanLines(file, text) {
  const out = scanTextForSecrets(text, file);
  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (/guardrails-ignore/i.test(line)) continue;
    for (const r of CODE_RULES) {
      r.regex.lastIndex = 0;
      if (r.regex.test(line)) {
        out.push({ ruleId: r.id, severity: r.severity, file, line: i + 1, message: r.msg });
      }
    }
  }
  return out;
}

function walkDir(dir, acc = []) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (SKIP_DIRS.has(entry.name)) continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) walkDir(full, acc);
    else if (SCAN_EXTS.has(path.extname(entry.name).toLowerCase())) acc.push(full);
  }
  return acc;
}

function main() {
  const args = process.argv.slice(2);
  const dirIdx = args.indexOf("--dir");
  const formatMd = args.includes("--markdown");
  const findings = [];

  if (dirIdx !== -1 && args[dirIdx + 1]) {
    const root = path.resolve(args[dirIdx + 1]);
    for (const file of walkDir(root)) {
      const rel = path.relative(root, file).replace(/\\/g, "/");
      findings.push(...scanLines(rel, fs.readFileSync(file, "utf8")));
    }
  } else {
    const baseIdx = args.indexOf("--base");
    const gitArgs = args.includes("--staged")
      ? ["diff", "--cached", "-U0"]
      : baseIdx !== -1 && args[baseIdx + 1]
        ? ["diff", `${args[baseIdx + 1]}...HEAD`, "-U0"]
        : ["diff", "-U0"];
    const diff = execFileSync("git", gitArgs, { encoding: "utf8", maxBuffer: 15 * 1024 * 1024 });
    let currentFile = "<diff>";
    const perFile = new Map();
    for (const line of diff.split(/\r?\n/)) {
      if (line.startsWith("+++ b/")) currentFile = line.slice(6);
      else if (line.startsWith("+") && !line.startsWith("+++")) {
        if (!perFile.has(currentFile)) perFile.set(currentFile, []);
        perFile.get(currentFile).push(line.slice(1));
      }
    }
    for (const [f, ls] of perFile.entries()) {
      findings.push(...scanLines(f, ls.join("\n")));
    }
  }

  const critical = findings.filter(f => f.severity === "CRITICAL").length;
  const high = findings.filter(f => f.severity === "HIGH").length;

  if (formatMd) {
    const lines = [
      "## AI Guardrails — Security Audit Report",
      `- **Total Findings:** ${findings.length} (CRITICAL: ${critical}, HIGH: ${high})`,
      ""
    ];
    if (findings.length === 0) {
      lines.push("No security issues detected.");
    } else {
      lines.push("| Severity | Rule | File:Line | Detail |", "| :--- | :--- | :--- | :--- |");
      for (const f of findings) {
        lines.push(`| ${f.severity} | ${f.ruleId} | ${f.file}:${f.line} | ${f.message || f.masked} |`);
      }
    }
    process.stdout.write(lines.join("\n") + "\n");
  } else {
    process.stdout.write(JSON.stringify({ ok: critical === 0 && high === 0, summary: { total: findings.length, critical, high }, findings }, null, 2) + "\n");
  }

  process.exit(critical > 0 || high > 0 ? 2 : 0);
}

main();
