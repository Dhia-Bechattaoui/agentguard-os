use std::collections::{HashMap, VecDeque};
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};

/// High-entropy secret patterns to redact.
static SECRET_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        // Stripe API Keys (test and live)
        Regex::new(r"sk_(test|live)_[0-9a-zA-Z]{24}").unwrap(),
        // Slack Tokens
        Regex::new(r"xox[bapr]-[0-9a-zA-Z]{10,48}").unwrap(),
        // AWS Access Key ID
        Regex::new(r"AKIA[0-9A-Z]{16}").unwrap(),
        // JWT tokens (JSON Web Tokens)
        Regex::new(r"eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*").unwrap(),
        // Generic synthetic placeholder format (e.g., __SECRET_PLACEHOLDER_STRIPE_KEY__)
        Regex::new(r"__SECRET_PLACEHOLDER_[A-Z0-9_]+__").unwrap(),
    ]
});

/// Vault for storing mappings between placeholders and actual secrets on the host.
#[derive(Debug, Clone, Default)]
pub struct SecretVault {
    mappings: HashMap<String, String>,
}

impl SecretVault {
    pub fn new() -> Self {
        Self {
            mappings: HashMap::new(),
        }
    }

    /// Registers a secret and returns a unique synthetic placeholder.
    pub fn register(&mut self, name: &str, real_value: &str) -> String {
        let placeholder = format!("__SECRET_PLACEHOLDER_{}__", name.to_uppercase().replace("-", "_"));
        self.mappings.insert(placeholder.clone(), real_value.to_string());
        placeholder
    }

    /// Retrieves the real value for a given placeholder, if it exists.
    pub fn lookup(&self, placeholder: &str) -> Option<&str> {
        self.mappings.get(placeholder).map(|s| s.as_str())
    }

    /// Returns a list of all registered placeholders.
    pub fn placeholders(&self) -> Vec<String> {
        self.mappings.keys().cloned().collect()
    }
}

/// Dynamic standard I/O streams and text censor.
pub struct OutputCensor {
    custom_placeholders: Vec<String>,
}

impl OutputCensor {
    pub fn new(vault: &SecretVault) -> Self {
        Self {
            custom_placeholders: vault.placeholders(),
        }
    }

    /// Redacts all high-entropy secrets and registered synthetic placeholders.
    pub fn censor(&self, text: &str) -> String {
        let mut censored = text.to_string();

        // 1. Redact high-entropy static regex patterns
        for pattern in SECRET_PATTERNS.iter() {
            censored = pattern.replace_all(&censored, "[REDACTED_SECRET]").to_string();
        }

        // 2. Redact specific dynamic placeholders we injected just in case they leak directly
        for placeholder in &self.custom_placeholders {
            if censored.contains(placeholder) {
                censored = censored.replace(placeholder, "[REDACTED_SECRET]");
            }
        }

        censored
    }
}

/// Structure representing network domain access rules.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct NetworkRule {
    pub domain: String,
    pub methods: Vec<String>,
    pub ports: Vec<u16>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct NetworkControlList {
    pub default_policy: String, // "block" or "allow"
    pub allowed_domains: Vec<NetworkRule>,
}

impl NetworkControlList {
    pub fn new(default_policy: &str) -> Self {
        Self {
            default_policy: default_policy.to_string(),
            allowed_domains: Vec::new(),
        }
    }

    pub fn add_rule(&mut self, domain: &str, methods: Vec<&str>, ports: Vec<u16>) {
        self.allowed_domains.push(NetworkRule {
            domain: domain.to_string(),
            methods: methods.into_iter().map(|m| m.to_uppercase()).collect(),
            ports,
        });
    }

    /// Checks if a request to a given host, port, and HTTP method is permitted.
    pub fn is_allowed(&self, host: &str, port: u16, method: &str) -> bool {
        let upper_method = method.to_uppercase();
        
        // Match specific rules
        for rule in &self.allowed_domains {
            let domain_matches = if rule.domain.starts_with("*.") {
                let suffix = &rule.domain[1..]; // ".github.com"
                host.ends_with(suffix) || host == &rule.domain[2..]
            } else {
                host == rule.domain
            };

            if domain_matches {
                let port_matches = rule.ports.contains(&port);
                let method_matches = rule.methods.iter().any(|m| m == &upper_method || m == "*");
                if port_matches && method_matches {
                    return true;
                }
            }
        }

        // Fallback to default policy
        self.default_policy == "allow"
    }
}

/// Dynamic Semantic Loop Detector for autonomous agents
#[derive(Debug, Clone)]
pub struct SemanticLoopDetector {
    history: VecDeque<String>,
    max_history_size: usize,
    similarity_threshold: f64,
}

impl SemanticLoopDetector {
    pub fn new(max_history_size: usize, similarity_threshold: f64) -> Self {
        Self {
            history: VecDeque::new(),
            max_history_size,
            similarity_threshold,
        }
    }

    /// Registers the agent's action input/output block in our sliding window history
    pub fn record_step(&mut self, text: &str) {
        if self.history.len() >= self.max_history_size {
            self.history.pop_front();
        }
        self.history.push_back(text.to_string());
    }

    /// Evaluates the Jaccard similarity score between two multi-line logs/actions
    pub fn jaccard_similarity(a: &str, b: &str) -> f64 {
        use std::collections::HashSet;

        let tokenize = |s: &str| -> HashSet<String> {
            s.split(|c: char| !c.is_alphanumeric())
                .filter(|word| !word.is_empty())
                .map(|word| word.to_lowercase())
                .collect()
        };

        let set_a = tokenize(a);
        let set_b = tokenize(b);

        if set_a.is_empty() && set_b.is_empty() {
            return 1.0;
        }

        let intersection: HashSet<_> = set_a.intersection(&set_b).collect();
        let union: HashSet<_> = set_a.union(&set_b).collect();

        intersection.len() as f64 / union.len() as f64
    }

    /// Checks if the latest registered step matches any previous action in our sliding window.
    /// Returns the similarity score and the repetitive text if a semantic loop is detected.
    pub fn detect_loop(&self) -> Option<(f64, String)> {
        if self.history.len() < 2 {
            return None;
        }

        let latest = &self.history[self.history.len() - 1];

        // Check against every item in history excluding the latest itself
        for i in 0..(self.history.len() - 1) {
            let prev = &self.history[i];
            let score = Self::jaccard_similarity(latest, prev);
            if score >= self.similarity_threshold {
                return Some((score, prev.clone()));
            }
        }

        None
    }

    pub fn history_len(&self) -> usize {
        self.history.len()
    }
}

/// Dynamic Execution & Financial Budget Tracker to prevent rogue agent billing
#[derive(Debug, Clone)]
pub struct ExecutionBudgetTracker {
    max_budget: f64,
    current_cost: f64,
    request_counts: HashMap<String, usize>,
}

impl ExecutionBudgetTracker {
    pub fn new(max_budget: f64) -> Self {
        Self {
            max_budget,
            current_cost: 0.0,
            request_counts: HashMap::new(),
        }
    }

    /// Charges the budget based on the specific API endpoint invoked by the agent
    pub fn charge_api(&mut self, url: &str, method: &str) -> Result<f64, String> {
        let clean_url = url.trim_start_matches("https://").trim_start_matches("http://");
        let domain = clean_url.split('/').next().unwrap_or("unknown");

        let cost = match domain {
            d if d.contains("slack.com") => 0.05,  // $0.05 per write/upload
            d if d.contains("github.com") => 0.01, // $0.01 per query
            _ => 0.005,                            // Default flat fee for custom requests
        };

        let new_cost = self.current_cost + cost;
        if new_cost > self.max_budget + 1e-9 {
            return Err(format!(
                "Budget Exceeded! Cumulative charge ${:.3} exceeds maximum limit of ${:.3} on method '{}' for '{}'",
                new_cost, self.max_budget, method, domain
            ));
        }

        self.current_cost = new_cost;
        let count = self.request_counts.entry(domain.to_string()).or_insert(0);
        *count += 1;

        Ok(self.current_cost)
    }

    pub fn current_cost(&self) -> f64 {
        self.current_cost
    }

    pub fn max_budget(&self) -> f64 {
        self.max_budget
    }

    pub fn request_count(&self, domain: &str) -> usize {
        self.request_counts.get(domain).cloned().unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secret_censorship() {
        let mut vault = SecretVault::default();
        vault.register("stripe_key", "sk_live_51Nabcdefghijklmnopqrstuv");

        let censor = OutputCensor::new(&vault);
        
        let output = "The API key was __SECRET_PLACEHOLDER_STRIPE_KEY__ and Stripe live key sk_live_123456789012345678901234.";
        let redacted = censor.censor(output);
        assert!(!redacted.contains("__SECRET_PLACEHOLDER_STRIPE_KEY__"));
        assert!(!redacted.contains("sk_live_123456789012345678901234"));
        assert_eq!(
            redacted,
            "The API key was [REDACTED_SECRET] and Stripe live key [REDACTED_SECRET]."
        );
    }

    #[test]
    fn test_network_rules() {
        let mut ncl = NetworkControlList::new("block");
        ncl.add_rule("api.github.com", vec!["GET", "POST"], vec![443]);
        ncl.add_rule("*.slack.com", vec!["POST"], vec![443, 80]);

        assert!(ncl.is_allowed("api.github.com", 443, "GET"));
        assert!(ncl.is_allowed("api.github.com", 443, "POST"));
        assert!(!ncl.is_allowed("api.github.com", 80, "GET"));
        assert!(!ncl.is_allowed("api.github.com", 443, "DELETE"));
        
        assert!(ncl.is_allowed("files.slack.com", 443, "POST"));
        assert!(ncl.is_allowed("slack.com", 80, "POST"));
        assert!(!ncl.is_allowed("files.slack.com", 443, "GET"));
        assert!(!ncl.is_allowed("malicious.com", 443, "GET"));
    }

    #[test]
    fn test_semantic_loop_detector() {
        let mut detector = SemanticLoopDetector::new(5, 0.80);

        // Step 1: Agent tries to search for a file
        detector.record_step("Agent action: search file 'config.json' in /etc. Result: permission denied");
        assert!(detector.detect_loop().is_none());

        // Step 2: Agent tries to write log
        detector.record_step("Agent action: write message to file '/sandbox/workspace/tmp/output.txt'");
        assert!(detector.detect_loop().is_none());

        // Step 3: Agent retries searching the same file with slightly different spacing
        detector.record_step("Agent action: Search file 'config.json' in /etc. Result: Permission Denied.");
        
        // This should trigger Jaccard similarity > 80%
        let loop_result = detector.detect_loop();
        assert!(loop_result.is_some());
        let (score, text) = loop_result.unwrap();
        assert!(score >= 0.80);
        assert!(text.contains("config.json"));
    }

    #[test]
    fn test_execution_budget_tracker() {
        let mut tracker = ExecutionBudgetTracker::new(0.12);

        // Charge 1: github.com query -> $0.01
        assert!(tracker.charge_api("https://api.github.com/repos", "GET").is_ok());
        assert!((tracker.current_cost() - 0.01).abs() < 0.0001);
        assert_eq!(tracker.request_count("api.github.com"), 1);

        // Charge 2: slack.com query -> $0.05
        assert!(tracker.charge_api("https://files.slack.com/upload", "POST").is_ok());
        assert!((tracker.current_cost() - 0.06).abs() < 0.0001);

        // Charge 3: slack.com query -> $0.05 (Total: 0.11)
        assert!(tracker.charge_api("https://files.slack.com/upload", "POST").is_ok());
        assert!((tracker.current_cost() - 0.11).abs() < 0.0001);

        // Charge 4: github.com query -> $0.01 (Total: 0.12)
        assert!(tracker.charge_api("https://api.github.com/repos", "GET").is_ok());
        assert!((tracker.current_cost() - 0.12).abs() < 0.0001);

        // Charge 5: another query -> exceeds limit!
        let result = tracker.charge_api("https://api.github.com/repos", "GET");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Budget Exceeded"));
    }
}
