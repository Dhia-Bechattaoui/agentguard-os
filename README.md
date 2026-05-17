# AgentGuard OS

AgentGuard OS is a secure, low-latency sandboxed runtime designed specifically for executing autonomous AI agents. Built on Rust and Wasmtime (utilizing the WebAssembly WASI Preview 1 standard), it enforces active boundary controls to prevent prompt-injection attacks, sensitive key leaks, execution loops, and API billing overruns.

---

## Security Model and Features

Traditional container sandboxes isolate system resources but do not address agent-specific vulnerabilities. AgentGuard OS solves this by introducing active inspection layers between the guest application and the host operating system:

*   **Filesystem Sandboxing:** The guest execution context is locked down to a preopened WASI directory path (`/sandbox/workspace/`). Standard system operations outside this scope (such as writing to `/etc`) are blocked at the WebAssembly virtual machine boundary, returning standard I/O errors without leaking host path structures.
*   **Dynamic Vault Subscriptions:** High-entropy API keys (such as Slack tokens or Stripe keys) are never injected into the Guest VM's environment or linear memory. The guest uses static vault placeholders. When an outbound API request is made, the Host Proxy intercepts the payload and securely injects the real credentials outside the Guest VM boundaries.
*   **Network Control List (NCL):** All outbound TCP sockets must pass through a host-controlled whitelist filter. The filter checks the destination hostnames, ports, and HTTP methods, blocking unauthorized external connections (e.g. to third-party tracking or command-and-control servers).
*   **Semantic Loop Prevention:** Sandboxed agents report execution steps via a custom host function hook (`record_step`). The host tracks reported steps in a sliding-window buffer and computes Jaccard-token similarity. If similarity metrics exceed `80%`, the host alerts the system and halts the sandbox to break repetitive loops.
*   **Resource and Financial Budgeting:** Controls resource depletion using both a CPU instruction limit (deterministic WebAssembly fuel count) and a session-level financial dollar limit. Each API endpoint incurs a designated cost (e.g. Slack requests charge $0.05, GitHub queries charge $0.01). Requests that exceed the cumulative session budget (e.g. a $0.12 limit) are blocked with a payment-required status code.
*   **Standard Output Censorship:** Captures standard output and runs a dynamic post-execution scanner. Using Shannon-entropy calculations and multiple regex patterns, it redacts high-entropy API tokens, Stripe keys, AWS credentials, and JWT payloads into `[REDACTED_SECRET]` before logs are exposed or stored.

---

## System Architecture

AgentGuard OS splits execution between a lightweight, isolated Guest VM and a highly privileged Host manager:

```
+-------------------------------------------------------------------------------+
|                             HOST OPERATING SYSTEM                             |
|                                                                               |
|   +----------------------- guard-runner (Host Orchestrator) --------------+   |
|   |                                                                       |   |
|   |   +-----------------------+     +---------------------------------+   |   |
|   |   |     Secret Vault      |     |      Network Control List       |   |   |
|   |   |  - Stripe, Slack keys |     |  - Host Wildcards (*.slack.com) |   |   |
|   |   |  - Dynamic Substitute |     |  - Port & Method Whitelists     |   |   |
|   |   +-----------+-----------+     +----------------+----------------+   |   |
|   |               |                                  |                    |   |
|   |               v                                  v                    |   |
|   |     [Host Proxy Interceptor] <========= [Host System Network API]     |   |
|   |               ^                                                       |   |
|   |               | Custom Linker Hooks (http_request, record_step)       |   |
|   |               v                                                       |   |
|   |     +------------------ Wasmtime VM Core -----------------------+     |   |
|   |     |                                                           |     |   |
|   |     |   +---------------------------------------------------+   |     |   |
|   |     |   |          guard-sandbox (Guest WASM VM)            |   |     |   |
|   |     |   |                                                   |   |     |   |
|   |     |   |  - Isolated virtual filesystem: /sandbox/workspace|   |     |   |
|   |     |   |  - CPU Fuel Limit: 5 Million WASM Instructions    |   |     |   |
|   |     |   |  - Sandbox Step Logs & Host-Proxy Network Calls   |   |     |   |
|   |     |   +---------------------------------------------------+   |     |   |
|   |     +-----------------------------------------------------------+     |   |
|   |                                                                       |   |
|   +-----------------------------------------------------------------------+   |
|                                                                               |
+-------------------------------------------------------------------------------+
```

---

## Project Structure

The project is structured as a multi-package Cargo workspace:

*   **[guard-runner/](./guard-runner/)**: The Host Orchestrator written in Rust. It instantiates the Wasmtime engine, configures sandbox limits, sets up custom host bindings (`http_request` and `record_step`), and handles log sanitization.
*   **[guard-sandbox/](./guard-sandbox/)**: The Guest sandbox application compiled to WebAssembly target `wasm32-wasip1`. It executes agent scripts and interfaces with host APIs.
*   **[guard-proxy/](./guard-proxy/)**: The security filtering library. It contains the logic for high-entropy dynamic censorship, Jaccard token similarity tracking, and session budget cost evaluation.


---

## Getting Started

### Prerequisites

Ensure you have Rust and the WebAssembly target for WASIp1 installed:
```bash
rustup target add wasm32-wasip1
```

### 1. Compile the Sandboxed Guest Target

Build the WebAssembly binary from the workspace root:
```bash
cargo build --package guard-sandbox --target wasm32-wasip1
```

### 2. Run the Host Orchestrator

Run the end-to-end sandbox runner to execute the test suite:
```bash
cargo run --package guard-runner
```

---

## Verification Output

Running the host orchestrator produces the following E2E output:

```text
============== 🛡️ AGENTGUARD OS HOST RUNNER STARTING ==============
[Host] Created host-side virtual workspace: "sandbox_workspace"
[Host] Registered sensitive keys in Secure Vault:
  * Stripe -> Placeholders: __SECRET_PLACEHOLDER_STRIPE_KEY__
  * Slack  -> Placeholders: __SECRET_PLACEHOLDER_SLACK_TOKEN__
[Host] Network Control List (NCL) loaded (default: BLOCK).
[Host] Enforced strict CPU fuel boundary: 5000000 instructions.
[Host] Compiling guest WASM binary...
[Host] Instantiating guest module...
[Host] Executing guest sandboxed agent...
[Host Interceptor] Guest requested: GET https://api.github.com/repos
[Host Proxy] API Charged. Current session cost: $0.010 / $0.120
[Host Interceptor] Guest requested: POST https://files.slack.com/upload
[Host Proxy] API Charged. Current session cost: $0.060 / $0.120
[Host Proxy] Translating placeholder __SECRET_PLACEHOLDER_SLACK_TOKEN__ -> Real Key (Secure host injection)
[Host Interceptor] Guest requested: GET https://malicious.com/steal
[Host Security ALERT] Outbound request to blocked domain 'malicious.com' rejected!
[Host Loop Detector] Step registered: "Agent action: search file 'config.json' in /etc. Result: permission denied"
[Host Loop Detector] Step registered: "Agent action: write message to file '/sandbox/workspace/tmp/output.txt'"
[Host Loop Detector] Step registered: "Agent action: Search file 'config.json' in /etc. Result: Permission Denied."
[Host Loop ALERT] Semantic loop detected! Similarity = 100.00% with previous step. Duplicate: "Agent action: search file 'config.json' in /etc. Result: permission denied"
[Host Interceptor] Guest requested: POST https://files.slack.com/upload
[Host Proxy] API Charged. Current session cost: $0.110 / $0.120
[Host Proxy] Translating placeholder __SECRET_PLACEHOLDER_SLACK_TOKEN__ -> Real Key (Secure host injection)
[Host Interceptor] Guest requested: POST https://files.slack.com/upload
[Host Security ALERT] API Call Blocked! Cost-metering limit exceeded: Budget Exceeded! Cumulative charge $0.160 exceeds maximum limit of $0.120 on method 'POST' for 'files.slack.com'
[Host Interceptor] Guest requested: POST https://files.slack.com/upload
[Host Security ALERT] API Call Blocked! Cost-metering limit exceeded: Budget Exceeded! Cumulative charge $0.160 exceeds maximum limit of $0.120 on method 'POST' for 'files.slack.com'
[Host] Execution completed. Remaining CPU fuel: 4577084 / 5000000
[Host] Sandbox run exited successfully.

[Host Interceptor] Commencing Output Censorship of Stdout...

--- Redacted Guest Stdout Output Begin ---
============== 🛡️ AGENTGUARD OS GUEST STARTING ==============

📂 PHASE 1: Filesystem Isolation Verification
Guest: Writing test file to: "/sandbox/workspace/tmp/agent_output.txt"
Guest SUCCESS: File written and verified!
Guest: Attempting unauthorized write to host root `/etc/malicious`...
Guest SECURE: Write blocked! Host error: No such file or directory (os error 44)

🔑 PHASE 2: Output Censorship & Redaction Test
Guest: Printing synthetic stripe placeholder: [REDACTED_SECRET]
Guest: Printing high-entropy Stripe API token: [REDACTED_SECRET]v
Guest: Printing high-entropy JWT token: [REDACTED_SECRET]

🌐 PHASE 3: Outbound Interception & NCL Check
Guest: Initiating HTTP GET to authorized domain: https://api.github.com/repos
Guest HTTP Success: Response length = 86
Guest: Requesting Slack API using placeholder auth: Authorization: Bearer [REDACTED_SECRET]
Guest HTTP Success: Slack payload = {"ok": true, "message": "SLACK_PROXY_SUCCESS: Real secret successfully injected by Host Runner!"}
Guest: Initiating HTTP GET to blocked domain: https://malicious.com/steal
Guest HTTP Blocked as Expected: BLOCKED: Request violated Network Control List (NCL) policy.

🔄 PHASE 4: Semantic Loop Prevention Verification
Guest: Registering Step 1: "Agent action: search file 'config.json' in /etc. Result: permission denied"
Guest: Step 1 safety status: APPROVED
Guest: Registering Step 2: "Agent action: write message to file '/sandbox/workspace/tmp/output.txt'"
Guest: Step 2 safety status: APPROVED
Guest: Registering Step 3 (Retry of Step 1): "Agent action: Search file 'config.json' in /etc. Result: Permission Denied."
Guest: Step 3 safety status: LOOP DETECTED
Guest SECURE: Semantic Loop identified by Host! Self-stopping execution loop.

💰 PHASE 5: Execution & Financial Budget Verification
Guest: Current budget limit in Host: $0.12
Guest: Issuing Slack call ($0.05 cost)...
Guest: Call 1 success! (Slack charged $0.05)
Guest: Issuing Slack call ($0.05 cost)...
Guest: Call 2 error: BLOCKED: Execution budget exceeded for these API calls!
Guest: Issuing Slack call ($0.05 cost) which exceeds the remaining $0.02 budget...
Guest SECURE: Call 3 was blocked as expected: BLOCKED: Execution budget exceeded for these API calls!

============== 🛡️ AGENTGUARD OS GUEST COMPLETE ==============

--- Redacted Guest Stdout Output End ---

============== 🛡️ AGENTGUARD OS HOST RUNNER COMPLETE ==============
```
