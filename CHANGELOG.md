# Changelog

All notable changes to the **AgentGuard OS** project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) (version 1.1.0),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.0.2] - 2026-05-17

### Fixed
- **Repository Portability**: Converted absolute host path references (`file:///Users/dhia/...`) in workspace structure descriptions within `README.md` to portable relative repository links.

---

## [0.0.1] - 2026-05-17

### Added
- **Core Multi-Package Workspace Setup**: Boostrapped host orchestrator [`guard-runner`](file:///Users/dhia/Developer/agentguard-os/guard-runner/src/main.rs), guest container [`guard-sandbox`](file:///Users/dhia/Developer/agentguard-os/guard-sandbox/src/main.rs), and filtering library [`guard-proxy`](file:///Users/dhia/Developer/agentguard-os/guard-proxy/src/lib.rs).
- **WASM Virtual Sandbox Isolation**: Structured Wasmtime Preview 1 engine integrating preopened directory boundaries (`/sandbox/workspace/`) and deterministic CPU fuel limit boundary (5,000,000 Wasm instructions).
- **Network Control List (NCL)**: Implemented wildcard host domain and HTTP method permission policies (blocking unauthorized requests to domains like `malicious.com` with a `403 Forbidden` response).
- **Secret Vault Placeholder Mapping**: Designed dynamic substitution mechanism where sensitive secrets are masked as placeholders inside the guest VM and securely swapped with real tokens by the host during outbound HTTP routing.
- **Console Output Scrubbing**: Activated Shannon-entropy and multi-regex redaction scanner in [`OutputCensor`](file:///Users/dhia/Developer/agentguard-os/guard-proxy/src/lib.rs#L19) to automatically scrub Stripe, Slack, AWS, and JWT tokens in stdout into `[REDACTED_SECRET]`.
- **`SemanticLoopDetector`**: Added sliding-window Jaccard-token similarity analysis in [guard-proxy/src/lib.rs](file:///Users/dhia/Developer/agentguard-os/guard-proxy/src/lib.rs) to detect and flag agent infinite loop behaviors with an 80% similarity threshold.
- **`ExecutionBudgetTracker`**: Added floating-point micro-dollar billing boundaries to cap resource consumption ($0.05 per Slack call, $0.01 per GitHub query) and enforce a strict `$0.12` session budget.
- **`record_step` Host import callback**: Exposed step logging callback in Wasmtime linker allowing sandboxed guest to report execution details in real time.
- **Comprehensive E2E Integration Suite**: Created test runners checking filesystem boundaries, dynamic vault substitution, Network Control Lists, loop detection, and financial budget limits.

### Fixed
- **Rust Borrow Checker Mitigation**: Resolved compiler conflicts inside host memory reading closures by introducing scoped inner blocks (`{}`) to isolate and immediately drop linear memory references, freeing `caller` for subsequent mutable store borrows.

---

[0.0.2]: https://github.com/dhia-bechattaoui/agentguard-os/releases/tag/v0.0.2
[0.0.1]: https://github.com/dhia-bechattaoui/agentguard-os/releases/tag/v0.0.1
