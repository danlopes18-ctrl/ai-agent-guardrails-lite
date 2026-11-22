#!/usr/bin/env node
/**
 * Hook #03 — Protected Files Guard (Claude Code PreToolUse Write/Edit)
 * Prevents AI agents from modifying .env*, private keys, lockfiles, .git internals,
 * or terraform state files unless GUARDRAILS_ALLOW_PROTECTED=1 is explicitly set.
 */
import { checkProtectedFile, readStdinText } from "./_lib/patterns.mjs";

async function main() {
  if (process.env.GUARDRAILS_ALLOW_PROTECTED === "1") {
    process.stdout.write(JSON.stringify({ decision: "allow", override: true }) + "\n");
    process.exit(0);
  }

  const args = process.argv.slice(2);
  let targetPath = args.includes("--path") ? args[args.indexOf("--path") + 1] : "";

  if (!targetPath) {
    const raw = (await readStdinText()).trim();
    if (raw) {
      try {
        const payload = JSON.parse(raw);
        const ti = payload.tool_input || payload;
        targetPath = ti.file_path || ti.Path || ti.path || "";
      } catch {
        targetPath = raw;
      }
    }
  }

  if (!targetPath) process.exit(0);

  const hits = checkProtectedFile(targetPath);
  if (hits.length > 0) {
    const reason = hits.map(h => `[${h.ruleId}] ${h.reason}`).join("; ");
    process.stderr.write(`[AI-GUARDRAILS BLOCKED] Protected file '${targetPath}': ${reason}\n`);
    process.stdout.write(JSON.stringify({ decision: "block", file: targetPath, hits }, null, 2) + "\n");
    process.exit(2);
  }

  process.stdout.write(JSON.stringify({ decision: "allow", file: targetPath }) + "\n");
  process.exit(0);
}

main().catch(err => {
  process.stderr.write(`[AI-GUARDRAILS ERROR] ${err.message}\n`);
  process.exit(1);
});
