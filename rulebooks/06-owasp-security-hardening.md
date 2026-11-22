# OWASP Top 10 AI-Assisted Development Guardrails

## Mandatory Security Controls
1. **Broken Access Control (A01):** Deny-by-default; verify object ownership (`record.orgId === session.orgId`) on every read/write/delete.
2. **Injection (A03):** Zero string interpolation in SQL, shell commands, LDAP, or HTML templates.
3. **SSRF (A10):** Resolve DNS and reject loopback (`127.0.0.0/8`, `::1`), link-local metadata (`169.254.169.254`), and RFC1918 ranges on any user-supplied URL.
4. **Secrets & Crypto (A02):** Use `crypto.timingSafeEqual` for webhook/HMAC comparison; never commit `.env`, keys, or JWT secrets.
5. **Supply Chain:** Audit every new dependency before installation; never run unverified `curl | sh`.
