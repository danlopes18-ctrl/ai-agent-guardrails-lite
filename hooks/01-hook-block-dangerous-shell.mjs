#!/usr/bin/env node
/**
 * Hook #01 — Dangerous Shell Command Guard (Claude Code PreToolUse / Cursor / CLI)
 * Reads Claude Code PreToolUse JSON on stdin (or --cmd "<command>").
 * Exit 2 blocks execution in Claude Code & prints reason to stderr. Exit 0 allows.
 */
import { checkDangerousShell, readStdinText } from "./_lib/patterns.mjs";

function parseArgCommand(argv) {
  const idx = argv.indexOf("--cmd");
  if (idx !== -1 && argv[idx + 1]) return argv[idx + 1];
  return null;
}

async function main() {
  let command = parseArgCommand(process.argv.slice(2));
  if (!command) {
    const raw = (await readStdinText()).trim();
    if (raw) {
      try {
        const payload = JSON.parse(raw);
        command =
          payload?.tool_input?.command ||
          payload?.tool_input?.CommandLine ||
          payload?.command ||
          "";
      } catch {
        command = raw;
      }
    }
  }

  if (!command) {
    process.exit(0);
  }

  const hits = checkDangerousShell(command);
  if (hits.length > 0) {
    const summary = hits.map(h => `[${h.severity}:${h.ruleId}] ${h.reason}`).join("; ");
    process.stderr.write(`[AI-GUARDRAILS BLOCKED] Dangerous shell command rejected: ${summary}\n`);
    process.stdout.write(JSON.stringify({ decision: "block", reason: summary, hits }, null, 2) + "\n");
    process.exit(2);
  }

  process.stdout.write(JSON.stringify({ decision: "allow" }) + "\n");
  process.exit(0);
}

main().catch(err => {
  process.stderr.write(`[AI-GUARDRAILS ERROR] ${err.message}\n`);
  process.exit(1);
});
