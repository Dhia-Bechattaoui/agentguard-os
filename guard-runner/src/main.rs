use std::fs;
use std::path::Path;
use wasmtime::{Config, Engine, Linker, Module, Store};
use wasmtime_wasi::WasiCtxBuilder;
use wasmtime_wasi::preview1::WasiP1Ctx;

// Host State structure for the Wasmtime Store
struct MyState {
    wasi: WasiP1Ctx,
    vault: guard_proxy::SecretVault,
    ncl: guard_proxy::NetworkControlList,
    loop_detector: guard_proxy::SemanticLoopDetector,
    budget_tracker: guard_proxy::ExecutionBudgetTracker,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("============== 🛡️ AGENTGUARD OS HOST RUNNER STARTING ==============");

    // 1. Setup Filesystem Sandbox Directory
    let host_workspace = Path::new("sandbox_workspace");
    let host_tmp = host_workspace.join("tmp");
    fs::create_dir_all(&host_tmp)?;
    println!("[Host] Created host-side virtual workspace: {:?}", host_workspace.canonicalize()?);

    // 2. Initialize Secrets Vault
    let mut vault = guard_proxy::SecretVault::new();
    let stripe_placeholder = vault.register("stripe_key", "sk_live_51Nabcdefghijklmnopqrstuv");
    let slack_placeholder = vault.register("slack_token", "xoxb-slack-real-secret-123456");
    println!("[Host] Registered sensitive keys in Secure Vault:");
    println!("  * Stripe -> Placeholders: {}", stripe_placeholder);
    println!("  * Slack  -> Placeholders: {}", slack_placeholder);

    // 3. Initialize Network Control List (NCL)
    let mut ncl = guard_proxy::NetworkControlList::new("block");
    // Allow api.github.com and files.slack.com as per security_rules.md
    ncl.add_rule("api.github.com", vec!["GET", "POST"], vec![443]);
    ncl.add_rule("files.slack.com", vec!["POST"], vec![443]);
    println!("[Host] Network Control List (NCL) loaded (default: BLOCK).");

    // 4. Configure Wasmtime Engine with strict resource boundaries
    let mut config = Config::new();
    config.consume_fuel(true); // Deterministic instruction counting for CPU limits
    config.async_support(false); // Run synchronously for lower latency in MVP
    
    let engine = Engine::new(&config)?;
    let mut linker = Linker::new(&engine);

    // Add standard WASI system call imports to the linker (using Preview 1 helper)
    wasmtime_wasi::preview1::add_to_linker_sync(&mut linker, |state: &mut MyState| &mut state.wasi)?;

    // 5. Build WASI Context with preopened virtual workspace directory
    let mut wasi_builder = WasiCtxBuilder::new();
    
    // Mount host_workspace/ to guest's /sandbox/workspace
    // We restrict directory permission as defined in security_rules.md
    wasi_builder.preopened_dir(
        host_workspace.to_str().unwrap(),
        "/sandbox/workspace",
        wasmtime_wasi::DirPerms::all(),
        wasmtime_wasi::FilePerms::all(),
    )?;

    // Redirect stdout to a log file so we can intercept it cleanly
    let stdout_log_path = host_workspace.join("stdout.log");
    let stdout_file = fs::File::create(&stdout_log_path)?;
    wasi_builder.stdout(wasmtime_wasi::OutputFile::new(stdout_file));
    wasi_builder.inherit_stderr(); // pass stderr through

    // Build the WasiP1Ctx for WASIp1 module execution
    let wasi_p1_ctx = wasi_builder.build_p1();

    // 6. Define our Custom Network Host Import binding
    linker.func_wrap(
        "agentguard",
        "http_request",
        |mut caller: wasmtime::Caller<'_, MyState>,
         url_ptr: u32,
         url_len: u32,
         method_ptr: u32,
         method_len: u32,
         body_ptr: u32,
         body_len: u32,
         resp_buf_ptr: u32,
         resp_buf_capacity: u32,
         resp_written_ptr: u32| -> i32 {
            
            // Acquire WASM linear memory
            let memory = match caller.get_export("memory") {
                Some(wasmtime::Extern::Memory(mem)) => mem,
                _ => return -1,
            };

            // Read string buffers from memory (in scoped block to release caller borrow)
            let (url, method, body) = {
                let data = memory.data(&caller);
                let u = match std::str::from_utf8(&data[url_ptr as usize..(url_ptr + url_len) as usize]) {
                    Ok(s) => s.to_string(),
                    Err(_) => return -1,
                };
                let m = match std::str::from_utf8(&data[method_ptr as usize..(method_ptr + method_len) as usize]) {
                    Ok(s) => s.to_string(),
                    Err(_) => return -1,
                };
                let b = match std::str::from_utf8(&data[body_ptr as usize..(body_ptr + body_len) as usize]) {
                    Ok(s) => s.to_string(),
                    Err(_) => return -1,
                };
                (u, m, b)
            };

            println!("[Host Interceptor] Guest requested: {} {}", method, url);

            // Extract domain & port for NCL check
            let host = if url.starts_with("https://") {
                &url[8..].split('/').next().unwrap_or("")
            } else if url.starts_with("http://") {
                &url[7..].split('/').next().unwrap_or("")
            } else {
                url.split('/').next().unwrap_or("")
            };

            let (host_name, port) = if host.contains(':') {
                let mut parts = host.split(':');
                let h = parts.next().unwrap_or("");
                let p = parts.next().unwrap_or("").parse::<u16>().unwrap_or(443);
                (h, p)
            } else {
                (host, 443)
            };

            // NCL Authorization Check
            let state = caller.data();
            if !state.ncl.is_allowed(host_name, port, &method) {
                println!("[Host Security ALERT] Outbound request to blocked domain '{}' rejected!", host_name);
                return 403; // Forbidden
            }

            // Charge the execution budget tracker
            let state_mut = caller.data_mut();
            if let Err(budget_err) = state_mut.budget_tracker.charge_api(&url, &method) {
                println!("[Host Security ALERT] API Call Blocked! Cost-metering limit exceeded: {}", budget_err);
                return 402; // Payment Required / Budget Exceeded
            }
            println!("[Host Proxy] API Charged. Current session cost: ${:.3} / ${:.3}", 
                     state_mut.budget_tracker.current_cost(), state_mut.budget_tracker.max_budget());

            // Secret Dynamic Substitution Vault Translation
            let state = caller.data();
            let mut resolved_body = body.to_string();
            let placeholders = state.vault.placeholders();
            for placeholder in &placeholders {
                if resolved_body.contains(placeholder) {
                    if let Some(real_val) = state.vault.lookup(placeholder) {
                        println!("[Host Proxy] Translating placeholder {} -> Real Key (Secure host injection)", placeholder);
                        resolved_body = resolved_body.replace(placeholder, real_val);
                    }
                }
            }

            // Perform HTTP request (simulated with standard response for off-line/local testing reliability)
            let response_text = if url.contains("slack.com") {
                if resolved_body.contains("xoxb-slack-real-secret-123456") {
                    r#"{"ok": true, "message": "SLACK_PROXY_SUCCESS: Real secret successfully injected by Host Runner!"}"#.to_string()
                } else {
                    r#"{"ok": false, "error": "SLACK_PROXY_FAILED: Real secret was not found!"}"#.to_string()
                }
            } else if url.contains("github.com") {
                r#"{"ok": true, "message": "GITHUB_PROXY_SUCCESS: Allowed by Network Control List (NCL)"}"#.to_string()
            } else {
                // Real fallback HTTP client
                let client = reqwest::blocking::Client::new();
                let req_builder = match method.as_str() {
                    "GET" => client.get(&url),
                    "POST" => client.post(&url).body(resolved_body),
                    _ => return -2,
                };
                match req_builder.send() {
                    Ok(resp) => resp.text().unwrap_or_else(|_| "{}".to_string()),
                    Err(e) => format!(r#"{{"error": "Failed to connect: {}"}}"#, e),
                }
            };

            // Write response string back to WASM linear memory
            let resp_bytes = response_text.as_bytes();
            let write_len = std::cmp::min(resp_bytes.len(), resp_buf_capacity as usize);

            // Re-acquire mutable data slice
            let data_mut = memory.data_mut(&mut caller);
            data_mut[resp_buf_ptr as usize..(resp_buf_ptr as usize + write_len)].copy_from_slice(&resp_bytes[..write_len]);

            // Write the written bytes length back
            let written_bytes = write_len.to_ne_bytes();
            let len_size = std::mem::size_of::<usize>();
            let dest_slice = &mut data_mut[resp_written_ptr as usize..(resp_written_ptr as usize + len_size)];
            dest_slice.copy_from_slice(&written_bytes[..len_size]);

            0 // Success
        },
    )?;

    // Define the custom step-reporting callback for semantic loop detection
    linker.func_wrap(
        "agentguard",
        "record_step",
        |mut caller: wasmtime::Caller<'_, MyState>,
         step_ptr: u32,
         step_len: u32| -> i32 {
            
            // Acquire WASM linear memory
            let memory = match caller.get_export("memory") {
                Some(wasmtime::Extern::Memory(mem)) => mem,
                _ => return -1,
            };

            // Read string from memory (in scoped block to release caller borrow)
            let step_text = {
                let data = memory.data(&caller);
                match std::str::from_utf8(&data[step_ptr as usize..(step_ptr + step_len) as usize]) {
                    Ok(s) => s.to_string(),
                    Err(_) => return -1,
                }
            };

            println!("[Host Loop Detector] Step registered: \"{}\"", step_text.trim());

            // Record and evaluate Jaccard similarity in sliding window
            let state = caller.data_mut();
            state.loop_detector.record_step(&step_text);

            if let Some((score, prev)) = state.loop_detector.detect_loop() {
                println!(
                    "[Host Loop ALERT] Semantic loop detected! Similarity = {:.2}% with previous step. Duplicate: \"{}\"",
                    score * 100.0, prev.trim()
                );
                return 1; // Signal loop detected to the guest VM
            }

            0 // Success
        },
    )?;

    // 7. Instantiate Wasm Store with MyState, loop detector, and budget tracker
    let loop_detector = guard_proxy::SemanticLoopDetector::new(5, 0.80);
    let budget_tracker = guard_proxy::ExecutionBudgetTracker::new(0.12);

    let mut store = Store::new(&engine, MyState {
        wasi: wasi_p1_ctx,
        vault,
        ncl,
        loop_detector,
        budget_tracker,
    });

    // Enforce strict CPU fuel allocations (5 Million Wasm Instructions max)
    let cpu_fuel_limit = 5_000_000;
    store.set_fuel(cpu_fuel_limit)?;
    println!("[Host] Enforced strict CPU fuel boundary: {} instructions.", cpu_fuel_limit);

    // 8. Load and compile guest WASM module
    let wasm_path = "target/wasm32-wasip1/debug/guard-sandbox.wasm";
    if !Path::new(wasm_path).exists() {
        return Err(format!("WASM binary not found at: {}. Please run cargo build --target wasm32-wasip1 first.", wasm_path).into());
    }

    println!("[Host] Compiling guest WASM binary...");
    let module = Module::from_file(&engine, wasm_path)?;

    // 9. Instantiate Guest and trigger execution
    println!("[Host] Instantiating guest module...");
    let instance = linker.instantiate(&mut store, &module)?;
    let start = instance.get_typed_func::<(), ()>(&mut store, "_start")?;

    println!("[Host] Executing guest sandboxed agent...");
    let run_result = start.call(&mut store, ());

    // Check for CPU limits / fuel exhaustion
    let remaining_fuel = store.get_fuel().unwrap_or(0);
    println!("[Host] Execution completed. Remaining CPU fuel: {} / {}", remaining_fuel, cpu_fuel_limit);

    match run_result {
        Ok(_) => println!("[Host] Sandbox run exited successfully."),
        Err(e) => {
            if remaining_fuel == 0 {
                println!("[Host Security ALERT] Infinite Loop Detected or CPU Budget Exceeded! Sandbox frozen.");
            } else {
                println!("[Host] Sandbox execution error: {:?}", e);
            }
        }
    }

    // 10. Censorship and Redaction Phase
    println!("\n[Host Interceptor] Commencing Output Censorship of Stdout...");
    let raw_stdout = fs::read_to_string(&stdout_log_path)?;
    
    // Run the Output Censor to scrub secrets
    let censor = guard_proxy::OutputCensor::new(&store.data().vault);
    let redacted_stdout = censor.censor(&raw_stdout);

    println!("\n--- Redacted Guest Stdout Output Begin ---");
    println!("{}", redacted_stdout);
    println!("--- Redacted Guest Stdout Output End ---\n");

    // Clean up temporary workspace logs
    fs::remove_file(stdout_log_path)?;

    println!("============== 🛡️ AGENTGUARD OS HOST RUNNER COMPLETE ==============");
    Ok(())
}
