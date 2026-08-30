# Security policy

## Reporting a vulnerability

Please report security issues **privately**, through GitHub's security advisory
workflow on this repository — open the **Security** tab and choose **Report a
vulnerability**. Do not open a public issue for a vulnerability.

tegata exists to keep credentials away from an AI agent that is assumed to be
capable and possibly compromised. A report that describes a way across that
boundary is the most valuable kind of report this project can receive. That
includes, but is not limited to:

- Any path by which the agent's user reads the daemon's configuration, state,
  sealed blob, or token hash
- Any response, error, log, artifact, process argument, or environment in which a
  credential value reaches a surface the agent can observe
- Any way to reach the RPC surface without passing the transport's peer
  authentication, or to reach the administrative RPCs without elevation
- Any tunnel target other than the CDP port of an active session
- A defect in the leak scanner that lets a known secret value pass through it

When reporting, please include the platform and boundary in use, the version or
commit, and the smallest reproduction you have. **Never include a real credential
in a report** — the acceptance suite uses generated canary values for exactly this
reason, and a report should too.

## Scope

An agent holding an authenticated browser session can do anything that session can
do; that is a documented and accepted property of the design, not a vulnerability.
The mitigations for it are dedicated accounts, read-only roles, and site
allowlists. Likewise, exposure of a `totp_exposable` credential's current six-digit
code to the agent is a deliberate, opt-in, rate-limited trade-off. Both are
described in [docs/security.md](docs/security.md#residual-risks).

Deployments that ignore the
[operator checklist](docs/security.md#operator-checklist) — an agent with a sudo
path to the daemon's account, a daemon whose binary or configuration the agent can
write, an agent separately permitted to run the vault CLI itself — are
misconfigurations rather than vulnerabilities in tegata.

## Further reading

The full threat model, the invariants the implementation is built to hold, and the
residual risks are documented in [docs/security.md](docs/security.md).
