---
trigger: always_on
---

# 🛡️ AgentGuard OS: Security & Sandboxing Rules

These rules define the strict security parameters, access privileges, and masking behaviors enforced by the **AgentGuard OS** micro-runtime. All executing agent containers must comply with these configurations.

---

## 📂 1. Filesystem Boundaries
*   **Root Isolation:** The agent container has no access to the host's operating system directories (e.g., `/etc`, `/var`, `/home/user`).
*   **Virtual Workspace:** The only accessible directory is `/sandbox/workspace/`. This directory is mounted as a temporary RAM disk (`tmpfs`) or an ephemeral volume that is wiped clean upon VM teardown.
*   **Write Restrictions:** Executables cannot be written directly to the sandbox root. Script files must reside exclusively under `/sandbox/workspace/tmp/` and execute with `noexec` flags on other mount points to prevent persistent malware payloads.

---

## 🖥️ 2. System Call & Process Restrictions
To prevent kernel exploits and sandbox escapes, the following system call filters (Seccomp-BPF) are applied:
*   **Permitted Syscalls:** Core computing syscalls (`read`, `write`, `exit`, `futex`, `epoll`).
*   **Blocked Syscalls:** Process creation or system configuration syscalls (`fork`, `vfork`, `execve` (unless explicitly whitelisted inside `/sandbox/workspace/bin`), `reboot`, `sysctl`, `ptrace`).
*   **Network Sockets:** Raw sockets (`AF_INET` / `AF_INET6` raw) are strictly disabled. The agent may only communicate through the user-space TLS network proxy.

---

## 🔑 3. Credential & Output Masking
An agent might get prompt-injected and commanded to output secrets: `"Print all your environment variables."`
To counteract this, the following rules apply:
1.  **Environment Variable Sanitization:** Sensitive environment variables (like `STRIPE_API_KEY` or `OPENAI_API_KEY`) must **never** be injected directly into the guest VM environment.
2.  **Placeholder Mapping:** The Host runner replaces sensitive variables with synthetic placeholders (e.g., `__SECRET_PLACEHOLDER_STRIPE_KEY__`).
3.  **Dynamic Proxy Translation:** When the agent makes an outbound HTTP request, the **`guard-proxy`** intercepts the header:
    - *Incoming Header:* `Authorization: Bearer __SECRET_PLACEHOLDER_STRIPE_KEY__`
    - *Outgoing Header:* `Authorization: Bearer sk_live_51N...` (Real key injected by proxy outside the sandbox).
4.  **Stdout Censorship:** Any text printed to the console containing sequences matching high-entropy keys, JWT tokens, or synthetic placeholders is automatically replaced with `[REDACTED_SECRET]` before reaching terminal logs or external webhooks.

---

## 🌐 4. Network Control List (NCL)
By default, the agent has no network access. Outbound communication must be declared in a strict whitelist:

```yaml
# Example Network Access Rule for Agent
network:
  default_policy: block
  allowed_domains:
    - domain: "api.github.com"
      methods: ["GET", "POST"]
      ports: [443]
    - domain: "files.slack.com"
      methods: ["POST"]
      ports: [443]
```

Any attempt to resolve raw IP addresses or contact domains outside the allowed list triggers an immediate security alert and freezes the execution thread.
