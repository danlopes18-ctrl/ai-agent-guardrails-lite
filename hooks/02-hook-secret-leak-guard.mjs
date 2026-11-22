#!/usr/bin/env node
/**
 * Hook #02 — Secret Leak Guard (Claude Code PreToolUse Write/Edit + Git Pre-Commit)
 * Scans proposed file content OR staged git diff for 11 secret patterns.
 * Always masks findings — never echoes raw secrets into agent logs.
 * Usage:
 *   echo '{"tool_input":{"file_path":"app.ts","content":"..."}}' | node hooks/02-hook-secret-leak-guard.mjs
 *   node hooks/02-hook-secret-leak-guard.mjs --staged
 *   node hooks/02-hook-secret-leak-guard.mjs --file path/to/file.ts
 */
import fs from "node:fs";
import { execFileSync } from "node:child_process";
import { scanTextForSecrets, readStdinText } from "./_lib/patterns.mjs";

async function main() {
  const args = process.argv.slice(2);
  let findings = [];

  if (args.includes("--staged")) {
    const diff = execFileSync("git", ["diff", "--cached", "-U0"], { encoding: "utf8", maxBuffer: 10 * 1024 * 1024 });
    let currentFile = "<staged>";
    const addedLines = [];
    for (const line of diff.split(/\r?\n/)) {
      if (line.startsWith("+++ b/")) {
        currentFile = line.slice(6);
      } else if (line.startsWith("+") && !line.startsWith("+++")) {
        addedLines.push({ file: currentFile, text: line.slice(1) });
      }
    }
    for (const item of addedLines) {
      findings.push(...scanTextForSecrets(item.text, item.file));
    }
  } else if (args.includes("--file")) {
    const filePath = args[args.indexOf("--file") + 1];
    if (!filePath || !fs.existsSync(filePath)) {
      process.stderr.write(`File not found: ${filePath}\n`);
      process.exit(1);
    }
    findings = scanTextForSecrets(fs.readFileSync(filePath, "utf8"), filePath);
  } else {
    const raw = (await readStdinText()).trim();
    if (raw) {
      try {
        const payload = JSON.parse(raw);
        const ti = payload.tool_input || payload;
        const file = ti.file_path || ti.Path || ti.path || "<tool_input>";
        const text = [ti.content, ti.new_string, ti.Replacement, ti.Content].filter(Boolean).join("\n");
        findings = scanTextForSecrets(text, file);
      } catch {
        findings = scanTextForSecrets(raw, "<stdin>");
      }
    }
  }

  if (findings.length > 0) {
    const msg = findings.map(f => `[${f.severity}:${f.ruleId}] ${f.file}:${f.line} (${f.masked})`).join(" | ");
    process.stderr.write(`[AI-GUARDRAILS BLOCKED] Potential secret detected: ${msg}\n`);
    process.stdout.write(JSON.stringify({ decision: "block", count: findings.length, findings }, null, 2) + "\n");
    process.exit(2);
  }

  process.stdout.write(JSON.stringify({ decision: "allow", count: 0 }) + "\n");
  process.exit(0);
}

main().catch(err => {
  process.stderr.write(`[AI-GUARDRAILS ERROR] ${err.message}\n`);
  process.exit(1);
});
