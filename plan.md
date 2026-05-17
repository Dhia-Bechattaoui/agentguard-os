# 🛡️ AgentGuard OS: Implementation Plan

## 1. Overview & Vision
**AgentGuard OS** is a specialized, secure runtime environment designed specifically for autonomous AI agents. Unlike standard Docker containers or sandboxes, AgentGuard OS provides native guardrails against agent-specific failure modes, including **Prompt Injection**, **Sensitive Data/Secret Leakage**, and **Infinite Execution Loops**.

```
                   +------------------------+
                   |   Autonomous Agent     |
                   |  (Python/JS/LangChain) |
                   +-----------+------------+
                               |
                               | Unfiltered System Calls / Shell Commands
                               v
+------------------------------+---------------------------------------+
|                       AgentGuard OS Sandbox                          |
|                                                                      |
|  +---------------------+  eBPF Proxy  +---------------------------+  |
|  | Isolated MicroVM    | ===========> | Dynamic Secret Filter     |  |
|  | (Wasm/Firecracker)  |              | * Regexes & AST Checking  |  |
|  +---------------------+              | * Dynamic PII Masking     |  |
|                                       +-------------+-------------+  |
|                                                     |                |
|  +---------------------+                            |                |
|  | Loop Detector       | <==========================+                |
|  | * Semantic Repeat   |                                             |
|  | * Call Frequency    |                                             |
|  +---------------------+                                             |
+-----------------------------------------------------|----------------+
                                                      v
                                              Safe Host Systems
                                            (Target APIs, Web, FS)
```

---

## 2. Key Capabilities
*   **WASM/MicroVM Sandboxing:** Execute agent-generated scripts and bash commands in extremely lightweight, isolated sandboxes (Wasmtime/Firecracker) with milli-second cold starts.
*   **eBPF-Powered Output Masking:** Dynamically intercept and filter all stdout/stderr and outbound network requests to mask API keys, database credentials, and personally identifiable information (PII) before they leave the environment.
*   **Semantic Loop Prevention:** Maintain a windowed execution history. If the agent starts executing the exact same instructions or gets stuck in a loop, AgentGuard OS freezes the VM and alerts a human administrator.
*   **Dynamic Capability Permissions:** Grant fine-grained, dynamic capabilities (e.g., "Write to `/tmp/data` only", "Allow HTTP GET to `api.github.com` only") on a per-step basis rather than granting the agent binary root access.

---

## 3. Core Architecture
The system is divided into three primary modules:
1.  **`guard-runner` (Host side):** The central manager written in Rust. It coordinates the sandbox, configures the environment, injects credentials, and exposes safe API bindings to the agent.
2.  **`guard-sandbox` (Guest side):** The secure container (WASM runtime or MicroVM) where the agent's code runs. It is completely isolated from the host filesystem.
3.  **`guard-proxy` (Network & I/O):** An inline interceptor that analyzes files, console outputs, and network packets to ensure no raw secrets are leaked.

---

## 4. Iterative Development Roadmap

### Phase 1: MVP Sandbox (WASM & MicroVM)
- [x] Set up the Rust-based Host runner using `wasmtime` and `firecracker-go-sdk`.
- [x] Expose standard shell execution interfaces (bash-in-wasm) with CPU/memory caps.
- [x] Define strict directory boundaries (only access `/sandbox/workspace`).

### Phase 2: Dynamic Secret Filtering
- [x] Implement the eBPF I/O interception layer.
- [x] Add regex and Shannon-entropy-based secret detection patterns (e.g., matching AWS keys, Stripe tokens).
- [x] Create a dynamic secret vault mapping: Host injects encrypted credentials, guest only sees placeholder values; `guard-proxy` swaps placeholders with actual secrets in outbound HTTP headers, completely hiding them from the agent code.

### Phase 3: Semantic Loop & Fraud Prevention
- [x] Build a sliding-window memory buffer tracking the agent's action inputs/outputs.
- [x] Implement similarity checking (Cosine/Cosine Jaccard similarity) on logs to detect semantic loops.
- [x] Add execution budget thresholds (e.g., total tokens, maximum CPU seconds, financial API cost caps).

---

## 5. Directory Structure
```
agentguard-os/
├── plan.md                <-- This plan
├── .agents/
│   ├── rules/
│   │   └── security_rules.md
│   └── workflows/
│       └── execution_workflow.md
├── guard-runner/          (Rust Host Manager)
├── guard-sandbox/         (WASM Sandbox Context)
└── guard-proxy/           (eBPF & Network Filter)
```
