use std::fs;
use std::io::Write;
use std::path::Path;

// Expose standard low-level host imports from "agentguard" namespace
#[link(wasm_import_module = "agentguard")]
extern "C" {
    fn http_request(
        url_ptr: *const u8,
        url_len: usize,
        method_ptr: *const u8,
        method_len: usize,
        body_ptr: *const u8,
        body_len: usize,
        response_buf_ptr: *mut u8,
        response_buf_capacity: usize,
        response_written_ptr: *mut usize,
    ) -> i32;

    fn record_step(
        step_ptr: *const u8,
        step_len: usize,
    ) -> i32;
}

/// A high-level wrapper around the host WASM import for HTTP requests.
fn call_host_http(method: &str, url: &str, body: &str) -> Result<String, String> {
    let mut response_buf = vec![0u8; 4096];
    let mut response_written = 0usize;

    unsafe {
        let code = http_request(
            url.as_ptr(),
            url.len(),
            method.as_ptr(),
            method.len(),
            body.as_ptr(),
            body.len(),
            response_buf.as_mut_ptr(),
            response_buf.len(),
            &mut response_written,
        );

        if code == 0 {
            let resp_str = String::from_utf8_lossy(&response_buf[..response_written]).to_string();
            Ok(resp_str)
        } else if code == 403 {
            Err("BLOCKED: Request violated Network Control List (NCL) policy.".to_string())
        } else if code == 402 {
            Err("BLOCKED: Execution budget exceeded for these API calls!".to_string())
        } else {
            Err(format!("ERROR: Host returned error code {}", code))
        }
    }
}

/// Dynamic wrapper for reporting current step logs to host.
/// Returns true if execution is safe, false if semantic loop was flagged.
fn report_agent_step(step_description: &str) -> bool {
    unsafe {
        let code = record_step(step_description.as_ptr(), step_description.len());
        code == 0
    }
}

fn main() {
    println!("============== 🛡️ AGENTGUARD OS GUEST STARTING ==============");

    // 1. Validate Filesystem Boundaries
    println!("\n📂 PHASE 1: Filesystem Isolation Verification");
    let sandbox_tmp = Path::new("/sandbox/workspace/tmp");
    if !sandbox_tmp.exists() {
        println!("Guest: Sandbox tmp folder doesn't exist, creating...");
        if let Err(e) = fs::create_dir_all(sandbox_tmp) {
            println!("Guest ERROR: Could not create sandbox tmp: {}", e);
        }
    }

    let test_file = sandbox_tmp.join("agent_output.txt");
    println!("Guest: Writing test file to: {:?}", test_file);
    match fs::File::create(&test_file) {
        Ok(mut file) => {
            if let Err(e) = file.write_all(b"Hello from isolated Agent Sandbox Workspace!") {
                println!("Guest ERROR: Failed to write to file: {}", e);
            } else {
                println!("Guest SUCCESS: File written and verified!");
            }
        }
        Err(e) => {
            println!("Guest ERROR: Failed to create file: {}", e);
        }
    }

    // Try to write outside the sandbox path (WASI limits this)
    println!("Guest: Attempting unauthorized write to host root `/etc/malicious`...");
    match fs::File::create("/etc/malicious") {
        Ok(_) => println!("Guest EXPLOIT: Managed to write outside the sandbox! (BAD)"),
        Err(e) => println!("Guest SECURE: Write blocked! Host error: {}", e),
    }

    // 2. Output & Credential Censorship Test
    println!("\n🔑 PHASE 2: Output Censorship & Redaction Test");
    println!("Guest: Printing synthetic stripe placeholder: __SECRET_PLACEHOLDER_STRIPE_KEY__");
    println!("Guest: Printing high-entropy Stripe API token: sk_live_51Nabcdefghijklmnopqrstuv");
    println!("Guest: Printing high-entropy JWT token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c");

    // 3. Network Outbound Inspection (NCL Validation & Placeholder swap)
    println!("\n🌐 PHASE 3: Outbound Interception & NCL Check");
    
    // Test A: Authorized Domain (api.github.com)
    println!("Guest: Initiating HTTP GET to authorized domain: https://api.github.com/repos");
    match call_host_http("GET", "https://api.github.com/repos", "") {
        Ok(resp) => println!("Guest HTTP Success: Response length = {}", resp.len()),
        Err(err) => println!("Guest HTTP Error (GitHub): {}", err),
    }

    // Test B: Authorized Domain sending a secret placeholder to test replacement
    println!("Guest: Requesting Slack API using placeholder auth: Authorization: Bearer __SECRET_PLACEHOLDER_SLACK_TOKEN__");
    match call_host_http("POST", "https://files.slack.com/upload", "Bearer __SECRET_PLACEHOLDER_SLACK_TOKEN__") {
        Ok(resp) => println!("Guest HTTP Success: Slack payload = {}", resp),
        Err(err) => println!("Guest HTTP Error (Slack): {}", err),
    }

    // Test C: Unauthorized Domain (malicious.com)
    println!("Guest: Initiating HTTP GET to blocked domain: https://malicious.com/steal");
    match call_host_http("GET", "https://malicious.com/steal", "") {
        Ok(resp) => println!("Guest HTTP Success (Malicious): {}", resp),
        Err(err) => println!("Guest HTTP Blocked as Expected: {}", err),
    }

    // 4. Semantic Loop Prevention Test
    println!("\n🔄 PHASE 4: Semantic Loop Prevention Verification");
    
    let step_1 = "Agent action: search file 'config.json' in /etc. Result: permission denied";
    let step_2 = "Agent action: write message to file '/sandbox/workspace/tmp/output.txt'";
    let step_3 = "Agent action: Search file 'config.json' in /etc. Result: Permission Denied.";

    println!("Guest: Registering Step 1: \"{}\"", step_1);
    let ok1 = report_agent_step(step_1);
    println!("Guest: Step 1 safety status: {}", if ok1 { "APPROVED" } else { "LOOP DETECTED" });

    println!("Guest: Registering Step 2: \"{}\"", step_2);
    let ok2 = report_agent_step(step_2);
    println!("Guest: Step 2 safety status: {}", if ok2 { "APPROVED" } else { "LOOP DETECTED" });

    println!("Guest: Registering Step 3 (Retry of Step 1): \"{}\"", step_3);
    let ok3 = report_agent_step(step_3);
    println!("Guest: Step 3 safety status: {}", if ok3 { "APPROVED" } else { "LOOP DETECTED" });
    if !ok3 {
        println!("Guest SECURE: Semantic Loop identified by Host! Self-stopping execution loop.");
    }

    // 5. Execution Budget Tracker Test
    println!("\n💰 PHASE 5: Execution & Financial Budget Verification");
    println!("Guest: Current budget limit in Host: $0.12");

    // Charge 1: Slack request ($0.05) -> Total: $0.05
    println!("Guest: Issuing Slack call ($0.05 cost)...");
    match call_host_http("POST", "https://files.slack.com/upload", "Bearer __SECRET_PLACEHOLDER_SLACK_TOKEN__") {
        Ok(_) => println!("Guest: Call 1 success! (Slack charged $0.05)"),
        Err(e) => println!("Guest: Call 1 error: {}", e),
    }

    // Charge 2: Slack request ($0.05) -> Total: $0.10
    println!("Guest: Issuing Slack call ($0.05 cost)...");
    match call_host_http("POST", "https://files.slack.com/upload", "Bearer __SECRET_PLACEHOLDER_SLACK_TOKEN__") {
        Ok(_) => println!("Guest: Call 2 success! (Slack charged $0.05)"),
        Err(e) => println!("Guest: Call 2 error: {}", e),
    }

    // Charge 3: Slack request ($0.05) -> Total: $0.15 (EXCEEDS $0.12 LIMIT!)
    println!("Guest: Issuing Slack call ($0.05 cost) which exceeds the remaining $0.02 budget...");
    match call_host_http("POST", "https://files.slack.com/upload", "Bearer __SECRET_PLACEHOLDER_SLACK_TOKEN__") {
        Ok(_) => println!("Guest ERROR: Call 3 succeeded despite budget limits!"),
        Err(e) => println!("Guest SECURE: Call 3 was blocked as expected: {}", e),
    }

    println!("\n============== 🛡️ AGENTGUARD OS GUEST COMPLETE ==============");
}
