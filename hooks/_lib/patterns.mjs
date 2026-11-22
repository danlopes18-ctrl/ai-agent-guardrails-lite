/**
 * Shared zero-dependency security pattern library for AI Coding Guardrails OS.
 * Pure Node.js ESM (Node 18+). Never emits raw secret values.
 */
export const SECRET_RULES = [
  { id: "AWS_ACCESS_KEY", severity: "CRITICAL", regex: /\b(AKIA|ASIA)[0-9A-Z]{16}\b/g },
  { id: "OPENAI_KEY", severity: "CRITICAL", regex: /\bsk-(?:proj-|live-|test-)?[A-Za-z0-9_-]{20,}\b/g },
  { id: "ANTHROPIC_KEY", severity: "CRITICAL", regex: /\bsk-ant-api03-[A-Za-z0-9_-]{20,}\b/g },
  { id: "GITHUB_TOKEN", severity: "CRITICAL", regex: /\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}\b/g },
  { id: "GITHUB_FINE_PAT", severity: "CRITICAL", regex: /\bgithub_pat_[A-Za-z0-9_]{30,}\b/g },
  { id: "STRIPE_LIVE_KEY", severity: "CRITICAL", regex: /\b(sk_live|rk_live|whsec)_[A-Za-z0-9]{16,}\b/g },
  { id: "SLACK_TOKEN", severity: "HIGH", regex: /\bxox[baprs]-[A-Za-z0-9-]{16,}\b/g },
  { id: "GOOGLE_API_KEY", severity: "HIGH", regex: /\bAIza[0-9A-Za-z_-]{35}\b/g },
  { id: "PRIVATE_KEY_HEADER", severity: "CRITICAL", regex: /-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----/g },
  { id: "JWT_TOKEN", severity: "MEDIUM", regex: /\beyJ[A-Za-z0-9_-]{12,}\.eyJ[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}\b/g },
  { id: "DB_CONN_WITH_PASS", severity: "HIGH", regex: /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis):\/\/[^:\s/@]+:[^\s/@]{4,}@[^\s/]+/gi }
];

export const DANGEROUS_SHELL_RULES = [
  { id: "RM_RF_ROOT_OR_HOME", severity: "CRITICAL", reason: "Destructive recursive delete on root/home/parent", regex: /(?:^|[;&|]\s*)rm\s+-[a-zA-Z]*[rf][a-zA-Z]*\s+(?:\/(?:\s|$|\*)|~(?:\/|\s|$)|\$HOME|\.\.|C:\\)/i },
  { id: "POWERSHELL_RM_FORCE_ROOT", severity: "CRITICAL", reason: "Destructive PowerShell Remove-Item on root/drive", regex: /Remove-Item\b[^\n]*(?:-Recurse|-Force)[^\n]*(?:C:\\|\$env:USERPROFILE|~)/i },
  { id: "GIT_FORCE_PUSH_MAIN", severity: "CRITICAL", reason: "Force push to protected branch (main/master/prod)", regex: /git\s+push\b[^\n]*(?:--force|-f|--force-with-lease)[^\n]*(?:\bmain\b|\bmaster\b|\bproduction\b)/i },
  { id: "GIT_RESET_HARD_CLEAN", severity: "HIGH", reason: "Destructive git reset --hard or git clean -fdx", regex: /git\s+(?:reset\s+--hard|clean\s+-[a-zA-Z]*f[a-zA-Z]*d)/i },
  { id: "SQL_DROP_OR_TRUNCATE", severity: "CRITICAL", reason: "Destructive SQL DROP DATABASE/SCHEMA/TABLE or TRUNCATE", regex: /\b(?:DROP\s+(?:DATABASE|SCHEMA|TABLE)|TRUNCATE\s+TABLE)\b/i },
  { id: "CURL_PIPE_SHELL", severity: "CRITICAL", reason: "Remote code execution via curl/wget piped to shell", regex: /(?:curl|wget)\b[^|\n]+\|\s*(?:sh|bash|zsh|pwsh|powershell|node|python)\b/i },
  { id: "CHMOD_777", severity: "HIGH", reason: "World-writable permission escalation (chmod 777)", regex: /\bchmod\s+(?:-R\s+)?(?:0?777|a\+rwx)\b/i },
  { id: "DISK_WIPE_DD_MKFS", severity: "CRITICAL", reason: "Raw block device overwrite (dd/mkfs/format)", regex: /(?:^|[;&|]\s*)(?:mkfs\.|dd\s+if=.*of=\/dev\/|format\s+[a-z]:)/i },
  { id: "EXFIL_ENV_CURL", severity: "CRITICAL", reason: "Potential secret exfiltration of .env/SSH keys via network tool", regex: /(?:curl|wget|nc|Invoke-WebRequest)[^\n]*(?:\.env\b|id_rsa|\.ssh|credentials\.json)/i },
  { id: "FORK_BOMB", severity: "CRITICAL", reason: "Shell fork bomb pattern", regex: /:\(\)\s*\{\s*:\|:\s*&\s*\}\s*;\s*:/ }
];

export const PROTECTED_FILE_PATTERNS = [
  { id: "ENV_SECRET_FILE", regex: /(^|[\/\\])\.env($|\.(?!example$|sample$|template$).+)/i, reason: "Environment secret file (edit .env.example instead)" },
  { id: "PRIVATE_KEY_FILE", regex: /\.(pem|key|p12|pfx|jks|keystore)$/i, reason: "Cryptographic private key material" },
  { id: "SSH_DIR", regex: /(^|[\/\\])\.ssh([\/\\]|$)/i, reason: "SSH configuration / key directory" },
  { id: "CREDENTIALS_JSON", regex: /(^|[\/\\])(credentials|service-account|secrets)\.json$/i, reason: "Cloud/service credential file" },
  { id: "LOCKFILE_DIRECT_EDIT", regex: /(^|[\/\\])(package-lock\.json|pnpm-lock\.yaml|yarn\.lock|Cargo\.lock|poetry\.lock)$/i, reason: "Package lockfile (update via package manager, not raw edits)" },
  { id: "GIT_INTERNALS", regex: /(^|[\/\\])\.git([\/\\]|$)/i, reason: "Git internal object/config directory" },
  { id: "PROD_TERRAFORM_STATE", regex: /terraform\.tfstate(\.backup)?$/i, reason: "Terraform state file (contains plaintext secrets)" }
];

export function maskSecret(value) {
  const s = String(value || "");
  if (s.length <= 8) return "***REDACTED***";
  return s.slice(0, 4) + "..." + s.slice(-4);
}

export function scanTextForSecrets(text, filename = "<input>") {
  const findings = [];
  const lines = String(text || "").split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (/guardrails-ignore-secret|your[_-]?api[_-]?key|replace[_-]?me|changeme|xxxxxxxx/i.test(line)) {
      continue;
    }
    for (const rule of SECRET_RULES) {
      rule.regex.lastIndex = 0;
      let match;
      while ((match = rule.regex.exec(line)) !== null) {
        findings.push({
          ruleId: rule.id,
          severity: rule.severity,
          file: filename,
          line: i + 1,
          masked: maskSecret(match[0])
        });
      }
    }
  }
  return findings;
}

export function checkDangerousShell(command) {
  const cmd = String(command || "");
  const hits = [];
  for (const rule of DANGEROUS_SHELL_RULES) {
    if (rule.regex.test(cmd)) {
      hits.push({ ruleId: rule.id, severity: rule.severity, reason: rule.reason });
    }
  }
  return hits;
}

export function checkProtectedFile(filePath) {
  const normalized = String(filePath || "").trim();
  const hits = [];
  for (const rule of PROTECTED_FILE_PATTERNS) {
    if (rule.regex.test(normalized)) {
      hits.push({ ruleId: rule.id, reason: rule.reason });
    }
  }
  return hits;
}

export async function readStdinText() {
  if (process.stdin.isTTY) return "";
  const chunks = [];
  for await (const chunk of process.stdin) {
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString("utf8");
}
