use destructive_command_guard::allowlist::LayeredAllowlist;
use destructive_command_guard::config::Config;
use destructive_command_guard::evaluator::evaluate_command;

#[test]
fn test_kubectl_in_heredoc_blocked() {
    let mut config = Config::default();
    config.heredoc.enabled = Some(true);
    config.packs.enabled = vec!["kubernetes.kubectl".to_string()];

    // We need to initialize the registry essentially (it's lazy static)
    // The evaluator handles this.

    let compiled = config.overrides.compile();
    let allowlists = LayeredAllowlist::default();

    // We need to make sure the keywords include 'kubectl' so quick reject doesn't kill it.
    // The top-level command is "bash", so "kubectl" is NOT in the top level.
    // Wait, check_triggers runs BEFORE quick_reject.
    // If check_triggers matches (it should for bash -c), then we enter evaluate_heredoc.
    // Inside evaluate_heredoc, we need to extract "kubectl delete..." and check it.

    // The top level command must match a trigger.
    let cmd = "bash -c 'kubectl delete namespace production'";

    // NOTE: For this test to work with the current evaluator logic (if it were working),
    // we pass the keywords for the *enabled packs* (kubectl).
    // The top-level command "bash ..." does NOT contain "kubectl" (wait, it does, in the string).
    // So quick reject allows it to pass if we pass ["kubectl"] as keywords.

    let keywords = vec!["kubectl"]; // Trigger keyword presence

    let result = evaluate_command(cmd, &config, &keywords, &compiled, &allowlists);

    assert!(result.is_denied(), "Should deny kubectl inside bash -c");
    assert_eq!(result.pack_id(), Some("kubernetes.kubectl"));
}
