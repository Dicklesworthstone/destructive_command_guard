//! Jenkins CI pack - protections for destructive Jenkins CLI/API operations.
//!
//! This pack targets high-impact Jenkins operations like deleting jobs,
//! removing nodes, deleting credentials, or wiping build history.

use crate::packs::{DestructivePattern, Pack, SafePattern};
use crate::{destructive_pattern, safe_pattern};

/// Create the Jenkins CI pack.
#[must_use]
pub fn create_pack() -> Pack {
    Pack {
        id: "cicd.jenkins".to_string(),
        name: "Jenkins",
        description: "Protects against destructive Jenkins CLI/API operations like deleting jobs, \
                      nodes, credentials, or build history.",
        keywords: &["jenkins-cli", "jenkins", "doDelete"],
        safe_patterns: create_safe_patterns(),
        destructive_patterns: create_destructive_patterns(),
        keyword_matcher: None,
        safe_regex_set: None,
        safe_regex_set_is_complete: false,
    }
}

fn create_safe_patterns() -> Vec<SafePattern> {
    vec![
        safe_pattern!(
            "jenkins-cli-list-jobs",
            r"(?:jenkins-cli|java\s+-jar\s+\S*jenkins-cli\.jar)(?:\s+--?\S+(?:\s+\S+)?)*\s+list-jobs\b"
        ),
        safe_pattern!(
            "jenkins-cli-get-job",
            r"(?:jenkins-cli|java\s+-jar\s+\S*jenkins-cli\.jar)(?:\s+--?\S+(?:\s+\S+)?)*\s+get-job\b"
        ),
        safe_pattern!(
            "jenkins-cli-build",
            r"(?:jenkins-cli|java\s+-jar\s+\S*jenkins-cli\.jar)(?:\s+--?\S+(?:\s+\S+)?)*\s+build\b"
        ),
        safe_pattern!(
            "jenkins-cli-who-am-i",
            r"(?:jenkins-cli|java\s+-jar\s+\S*jenkins-cli\.jar)(?:\s+--?\S+(?:\s+\S+)?)*\s+who-am-i\b"
        ),
        safe_pattern!(
            "jenkins-cli-list-views",
            r"(?:jenkins-cli|java\s+-jar\s+\S*jenkins-cli\.jar)(?:\s+--?\S+(?:\s+\S+)?)*\s+list-views\b"
        ),
        safe_pattern!(
            "jenkins-cli-list-plugins",
            r"(?:jenkins-cli|java\s+-jar\s+\S*jenkins-cli\.jar)(?:\s+--?\S+(?:\s+\S+)?)*\s+list-plugins\b"
        ),
        safe_pattern!(
            "jenkins-cli-get-node",
            r"(?:jenkins-cli|java\s+-jar\s+\S*jenkins-cli\.jar)(?:\s+--?\S+(?:\s+\S+)?)*\s+get-node\b"
        ),
        safe_pattern!(
            "jenkins-cli-get-credentials",
            r"(?:jenkins-cli|java\s+-jar\s+\S*jenkins-cli\.jar)(?:\s+--?\S+(?:\s+\S+)?)*\s+get-credentials\b"
        ),
        safe_pattern!(
            "jenkins-curl-explicit-get",
            r"curl(?:\s+--?\S+(?:\s+\S+)?)*\s+(?:-X|--request)\s+GET\b.*(?:jenkins|/job/|/api/)"
        ),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        destructive_pattern!(
            "jenkins-cli-delete-job",
            r"(?:jenkins-cli|java\s+-jar\s+\S*jenkins-cli\.jar)(?:\s+--?\S+(?:\s+\S+)?)*\s+delete-job\b",
            "jenkins-cli delete-job deletes Jenkins jobs and can break pipelines."
        ),
        destructive_pattern!(
            "jenkins-cli-delete-node",
            r"(?:jenkins-cli|java\s+-jar\s+\S*jenkins-cli\.jar)(?:\s+--?\S+(?:\s+\S+)?)*\s+delete-node\b",
            "jenkins-cli delete-node deletes Jenkins nodes and can halt CI."
        ),
        destructive_pattern!(
            "jenkins-cli-delete-credentials",
            r"(?:jenkins-cli|java\s+-jar\s+\S*jenkins-cli\.jar)(?:\s+--?\S+(?:\s+\S+)?)*\s+delete-credentials\b",
            "jenkins-cli delete-credentials removes stored credentials."
        ),
        destructive_pattern!(
            "jenkins-cli-delete-builds",
            r"(?:jenkins-cli|java\s+-jar\s+\S*jenkins-cli\.jar)(?:\s+--?\S+(?:\s+\S+)?)*\s+delete-builds\b",
            "jenkins-cli delete-builds removes build history and artifacts."
        ),
        destructive_pattern!(
            "jenkins-cli-delete-view",
            r"(?:jenkins-cli|java\s+-jar\s+\S*jenkins-cli\.jar)(?:\s+--?\S+(?:\s+\S+)?)*\s+delete-view\b",
            "jenkins-cli delete-view removes Jenkins views."
        ),
        destructive_pattern!(
            "jenkins-curl-do-delete",
            r"curl(?:\s+--?\S+(?:\s+\S+)?)*\s+(?:-X|--request)\s+POST\b.*\bdoDelete\b",
            "curl POST to Jenkins doDelete endpoints deletes jobs or resources."
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packs::test_helpers::*;

    #[test]
    fn test_pack_creation() {
        let pack = create_pack();
        assert_eq!(pack.id, "cicd.jenkins");
        assert_eq!(pack.name, "Jenkins");
        assert!(!pack.description.is_empty());
        assert!(pack.keywords.contains(&"jenkins-cli"));

        assert_patterns_compile(&pack);
        assert_all_patterns_have_reasons(&pack);
        assert_unique_pattern_names(&pack);
    }

    #[test]
    fn test_job_delete_blocked() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "java -jar jenkins-cli.jar -s http://jenkins.local/ delete-job my-job",
            "jenkins-cli-delete-job",
        );
    }

    #[test]
    fn test_node_delete_blocked() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "java -jar jenkins-cli.jar -s http://jenkins.local/ delete-node agent-1",
            "jenkins-cli-delete-node",
        );
    }

    #[test]
    fn test_credentials_delete_blocked() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "java -jar jenkins-cli.jar -s http://jenkins.local/ delete-credentials system::system::foo",
            "jenkins-cli-delete-credentials",
        );
    }

    #[test]
    fn test_build_delete_blocked() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "java -jar jenkins-cli.jar -s http://jenkins.local/ delete-builds my-job 100..200",
            "jenkins-cli-delete-builds",
        );
    }

    #[test]
    fn test_curl_do_delete_blocked() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "curl -X POST https://jenkins.example/job/my-job/doDelete",
            "jenkins-curl-do-delete",
        );
    }

    #[test]
    fn test_view_delete_blocked() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "java -jar jenkins-cli.jar -s http://jenkins.local/ delete-view prod-view",
            "jenkins-cli-delete-view",
        );
    }

    #[test]
    fn test_safe_commands_allowed() {
        let pack = create_pack();
        assert_allows(
            &pack,
            "java -jar jenkins-cli.jar -s http://jenkins.local/ list-jobs",
        );
        assert_allows(
            &pack,
            "java -jar jenkins-cli.jar -s http://jenkins.local/ who-am-i",
        );
        assert_allows(
            &pack,
            "java -jar jenkins-cli.jar -s http://jenkins.local/ get-job my-job",
        );
        assert_allows(
            &pack,
            "java -jar jenkins-cli.jar -s http://jenkins.local/ list-views",
        );
        assert_allows(
            &pack,
            "java -jar jenkins-cli.jar -s http://jenkins.local/ list-plugins",
        );
        assert_allows(
            &pack,
            "java -jar jenkins-cli.jar -s http://jenkins.local/ get-node agent-1",
        );
        assert_allows(
            &pack,
            "java -jar jenkins-cli.jar -s http://jenkins.local/ get-credentials system::system::foo",
        );
        assert_allows(&pack, "jenkins-cli build my-job");
        assert_allows(&pack, "curl -X GET https://jenkins.example/api/json");
    }
}
