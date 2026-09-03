//! Azure DevOps CLI patterns — the `azure-devops` Azure CLI extension.
//!
//! Scope (issue #385): the command groups the `azure-devops` extension adds to
//! `az` — `az devops`, `az repos`, `az pipelines`, `az boards` and
//! `az artifacts`. The extension installs itself the first time one of those
//! commands runs, so its surface is present on any workstation that has `az`.
//!
//! This is deliberately a separate pack from `cloud.azure`: that pack guards
//! Azure *resources* (subscriptions, VMs, storage, Key Vault), while these
//! commands act on an Azure DevOps *organization* (projects, repositories,
//! pipelines, boards, permissions). They are enabled independently.
//!
//! Coverage boundary, stated so it can be checked against the reference:
//!
//! - Only **GA** commands are modelled. The `az devops migrations *` group is
//!   Preview and its verbs (`abandon`, `pause`, `pipelines delete`) are
//!   deliberately not rules yet — the group is still changing shape.
//! - `az artifacts` has **no** destructive command: the whole documented group
//!   is `az artifacts universal download` and `az artifacts universal publish`.
//!   Nothing to guard, and no rule pretends otherwise.
//! - `az devops invoke` can issue an arbitrary Azure DevOps REST call, so it is
//!   matched on its `--http-method` rather than on a resource verb.
//! - Read-only verbs (`list`, `show`, `list-*`, `search`) and ordinary
//!   development flow (`az repos pr create`, `az pipelines run`,
//!   `az boards work-item create`) carry no rule and are allowed by default.
//!
//! Reference: <https://learn.microsoft.com/en-us/cli/azure/devops>

use crate::packs::{DestructivePattern, Pack, SafePattern};
use crate::{destructive_pattern, safe_pattern};

/// Create the Azure DevOps pack.
#[must_use]
pub fn create_pack() -> Pack {
    Pack {
        id: "platform.azure_devops".to_string(),
        name: "Azure DevOps CLI",
        description: "Protects against destructive Azure DevOps CLI extension operations \
                      like project delete, repos delete, pipeline delete, and permission reset",
        keywords: &[
            "az", "devops", "repos", "pipelines", "boards", "artifacts",
        ],
        safe_patterns: create_safe_patterns(),
        destructive_patterns: create_destructive_patterns(),
        keyword_matcher: None,
        safe_regex_set: None,
        safe_regex_set_is_complete: false,
    }
}

fn create_safe_patterns() -> Vec<SafePattern> {
    vec![
        // Help output (the #380 convention). Every `az` command documents
        // `--help -h  Show this help message and exit`; help prints usage and
        // exits before any REST call. A quoted token is consumed whole so a
        // `--help` inside an argument (`--name 'x --help'`) is not the flag,
        // and the walk stops at redirection/separator characters so
        // `az repos delete --id 1 --yes > --help` stays a deletion.
        safe_pattern!(
            "az-devops-help",
            r"(?<![\w-])az(?:\s+(?:\x22[^\x22]*\x22|'[^']*'|(?!--(?:\s|$))[^\s;&|<>\x22']+))*\s+--help(?![\w-])"
        ),
        safe_pattern!(
            "az-devops-help-short",
            r"(?<![\w-])az(?:\s+(?:\x22[^\x22]*\x22|'[^']*'|(?!--(?:\s|$))[^\s;&|<>\x22']+))*\s+-h(?![\w-])"
        ),
    ]
}

/// `az` accepts global flags (`--subscription`, `--debug`, `--output`, …)
/// between the executable and the command group, so every rule reaches its
/// group with a lazy `.*?` exactly like the `cloud.azure` pack.
///
/// Each group word opens with `(?<![\w-])` so a longer hyphenated word cannot
/// claim the rule, and each terminal verb closes with `(?![\w-])` so a
/// hyphenated sibling subcommand cannot inherit it — the `delete` /
/// `delete-asset` failure from #380.
#[allow(clippy::too_many_lines)]
fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        // ---- az devops (organization level) --------------------------------
        destructive_pattern!(
            "devops-project-delete",
            r"az\b.*?(?<![\w-])devops\s+project\s+delete(?![\w-])",
            "az devops project delete destroys a team project and every repository, pipeline, board and wiki in it.",
            Critical,
            "devops project delete removes an entire Azure DevOps team project:\n\n\
             - ALL Git repositories in the project are deleted\n\
             - ALL pipelines, releases, variable groups and service connections go\n\
             - ALL work items, boards, queries and wikis go\n\
             - Deleted projects sit in a recycle bin for a limited window and are\n  \
             then purged; recovery is a portal/support operation, not a CLI one\n\n\
             Inventory the project first:\n  \
             az repos list --project PROJECT -o table\n  \
             az pipelines list --project PROJECT -o table"
        ),
        destructive_pattern!(
            "devops-team-delete",
            r"az\b.*?(?<![\w-])devops\s+team\s+delete(?![\w-])",
            "az devops team delete removes a team along with its board configuration.",
            High,
            "devops team delete removes an Azure DevOps team:\n\n\
             - The team's backlog, boards, sprints and dashboards are removed\n\
             - Area/iteration assignments made to the team are lost\n\
             - Work items survive; the views onto them do not\n\n\
             Record the configuration first:\n  \
             az devops team show --team TEAM --project PROJECT"
        ),
        destructive_pattern!(
            "devops-user-remove",
            r"az\b.*?(?<![\w-])devops\s+user\s+remove(?![\w-])",
            "az devops user remove revokes a user's access to the whole organization.",
            High,
            "devops user remove removes a user from the organization:\n\n\
             - The user loses access to every project immediately\n\
             - Group memberships and per-project permissions are dropped\n\
             - Their license is released and must be re-assigned on re-add\n\
             - Work item history keeps the identity, so nothing is anonymised\n\n\
             Downgrade instead of removing:\n  \
             az devops user update --user USER --license-type stakeholder"
        ),
        destructive_pattern!(
            "devops-security-group-delete",
            r"az\b.*?(?<![\w-])devops\s+security\s+group\s+delete(?![\w-])",
            "az devops security group delete removes a security group and every permission granted through it.",
            High,
            "devops security group delete removes an Azure DevOps group:\n\n\
             - Every member loses the permissions the group granted\n\
             - ACL entries naming the group are dropped, not transferred\n\
             - Pipelines and policies that reference the group start failing\n\n\
             List the membership first:\n  \
             az devops security group membership list --id GROUP-DESCRIPTOR"
        ),
        destructive_pattern!(
            "devops-security-group-membership-remove",
            r"az\b.*?(?<![\w-])devops\s+security\s+group\s+membership\s+remove(?![\w-])",
            "az devops security group membership remove revokes a user's or group's membership.",
            Medium,
            "devops security group membership remove drops a membership:\n\n\
             - The member loses every permission inherited from the group\n\
             - Nested groups lose it transitively\n\
             - Re-adding restores access, so this is recoverable\n\n\
             Confirm the effect first:\n  \
             az devops security permission list --id NAMESPACE --subject SUBJECT"
        ),
        destructive_pattern!(
            "devops-security-permission-reset-all",
            r"az\b.*?(?<![\w-])devops\s+security\s+permission\s+reset-all(?![\w-])",
            "az devops security permission reset-all clears EVERY permission on a token for a user or group.",
            High,
            "devops security permission reset-all clears an entire ACL entry:\n\n\
             - Every allow AND deny bit for that subject on that token is removed\n\
             - Explicit DENY rules that were holding back access disappear too,\n  \
             so this can silently WIDEN access, not only narrow it\n\
             - There is no per-bit undo; the ACL must be rebuilt\n\n\
             Capture the current ACL first:\n  \
             az devops security permission show --id NAMESPACE --subject SUBJECT --token TOKEN"
        ),
        destructive_pattern!(
            "devops-security-permission-reset",
            r"az\b.*?(?<![\w-])devops\s+security\s+permission\s+reset(?![\w-])",
            "az devops security permission reset clears the named permission bits for a user or group.",
            Medium,
            "devops security permission reset clears specific permission bits:\n\n\
             - The named bits revert to inherited, which may allow or deny\n\
             - Clearing a DENY bit can grant access rather than remove it\n\n\
             Capture the current ACL first:\n  \
             az devops security permission show --id NAMESPACE --subject SUBJECT --token TOKEN"
        ),
        destructive_pattern!(
            "devops-service-endpoint-delete",
            r"az\b.*?(?<![\w-])devops\s+service-endpoint\s+delete(?![\w-])",
            "az devops service-endpoint delete removes a service connection and its stored credentials.",
            High,
            "devops service-endpoint delete removes a service connection:\n\n\
             - Every pipeline using the connection fails on its next run\n\
             - The stored secret (service principal key, PAT, cloud credential)\n  \
             is destroyed and cannot be read back from Azure DevOps\n\
             - Re-creating it needs the original credential material again\n\n\
             Find the users first:\n  \
             az devops service-endpoint show --id ENDPOINT-ID"
        ),
        destructive_pattern!(
            "devops-wiki-delete",
            r"az\b.*?(?<![\w-])devops\s+wiki\s+delete(?![\w-])",
            "az devops wiki delete removes a wiki and all of its pages.",
            High,
            "devops wiki delete removes an Azure DevOps wiki:\n\n\
             - Every page and attachment in the wiki goes\n\
             - A project wiki is backed by a Git repository; a code wiki is\n  \
             backed by a repo you own, so check which kind this is before\n  \
             assuming the content survives elsewhere\n\n\
             Identify the wiki first:\n  \
             az devops wiki show --wiki WIKI --project PROJECT"
        ),
        destructive_pattern!(
            "devops-wiki-page-delete",
            r"az\b.*?(?<![\w-])devops\s+wiki\s+page\s+delete(?![\w-])",
            "az devops wiki page delete removes a wiki page and its subtree.",
            Medium,
            "devops wiki page delete removes a page:\n\n\
             - Child pages under the path are removed with it\n\
             - A project wiki keeps Git history, so the content is recoverable\n  \
             from the backing repository\n\n\
             Read it first:\n  \
             az devops wiki page show --path PATH --wiki WIKI"
        ),
        destructive_pattern!(
            "devops-extension-uninstall",
            r"az\b.*?(?<![\w-])devops\s+extension\s+uninstall(?![\w-])",
            "az devops extension uninstall removes a marketplace extension organization-wide.",
            Medium,
            "devops extension uninstall removes an extension from the organization:\n\n\
             - Pipeline tasks, widgets and hubs the extension provided disappear\n\
             - Pipelines that reference its tasks fail to compile\n\
             - Extension-owned data may be deleted with it\n\n\
             Disable instead to keep the data:\n  \
             az devops extension disable --extension-id ID --publisher-id PUB"
        ),
        destructive_pattern!(
            "devops-logout",
            r"az\b.*?(?<![\w-])devops\s+logout(?![\w-])",
            "az devops logout clears the stored Azure DevOps credential; with no --org it clears every organization.",
            Medium,
            "devops logout drops the cached PAT:\n\n\
             - Without `--org`, ALL organizations are logged out at once\n\
             - Nothing in Azure DevOps is destroyed, but every later\n  \
             `az devops` / `az repos` / `az pipelines` command in this\n  \
             environment fails until a PAT is supplied again\n\n\
             Scope the logout:\n  \
             az devops logout --org https://dev.azure.com/ORG"
        ),
        // `az devops invoke` is a generic REST client for the whole Azure
        // DevOps API, so there is no resource verb to key on — the HTTP method
        // is the only signal that the call changes state.
        destructive_pattern!(
            "devops-invoke-delete",
            r"az\b.*?(?<![\w-])devops\s+invoke(?![\w-])[^\n;&|]*?--http-method[=\s]+(?i:delete)(?![\w-])",
            "az devops invoke --http-method DELETE issues an arbitrary Azure DevOps DELETE request.",
            High,
            "devops invoke with DELETE calls the raw Azure DevOps REST API:\n\n\
             - Any resource the API exposes can be deleted this way — projects,\n  \
             repositories, pipelines, policies, permissions\n\
             - No CLI confirmation prompt and no `--yes` gate applies\n\
             - dcg cannot tell WHICH resource this targets, so it is treated as\n  \
             the most destructive call the named area/resource allows\n\n\
             Preview the same call read-only first:\n  \
             az devops invoke --area AREA --resource RESOURCE --http-method GET"
        ),
        destructive_pattern!(
            "devops-invoke-write",
            r"az\b.*?(?<![\w-])devops\s+invoke(?![\w-])[^\n;&|]*?--http-method[=\s]+(?i:put|patch|post)(?![\w-])",
            "az devops invoke with PUT/PATCH/POST issues an arbitrary state-changing Azure DevOps request.",
            Medium,
            "devops invoke with PUT/PATCH/POST calls the raw Azure DevOps REST API:\n\n\
             - A PUT or PATCH overwrites the target resource's state; a POST can\n  \
             create or trigger one\n\
             - Overwriting a policy, permission ACL or pipeline definition can\n  \
             remove protection as effectively as a delete\n\n\
             Read the current state first:\n  \
             az devops invoke --area AREA --resource RESOURCE --http-method GET"
        ),
        // ---- az repos ------------------------------------------------------
        destructive_pattern!(
            "repos-delete",
            r"az\b.*?(?<![\w-])repos\s+delete(?![\w-])",
            "az repos delete destroys a Git repository and its entire history.",
            Critical,
            "repos delete removes an Azure Repos Git repository:\n\n\
             - Every branch, tag and commit on the server is destroyed\n\
             - Pull requests, policies and their review history go with it\n\
             - Pipelines pointing at the repository break\n\
             - `--yes` skips the confirmation prompt entirely\n\n\
             A local clone is the only remaining copy. Verify one exists and is\n\
             current before running this:\n  \
             az repos show --repository REPO --project PROJECT"
        ),
        destructive_pattern!(
            "repos-ref-delete",
            r"az\b.*?(?<![\w-])repos\s+ref\s+delete(?![\w-])",
            "az repos ref delete removes a server-side branch or tag.",
            High,
            "repos ref delete removes a Git reference on the server:\n\n\
             - Commits reachable only from that ref become unreferenced and are\n  \
             garbage-collected in time\n\
             - Deleting a release tag breaks reproducible builds\n\
             - Open pull requests targeting the branch are abandoned\n\n\
             Record the object id so the ref can be re-created:\n  \
             az repos ref list --repository REPO --filter heads/BRANCH"
        ),
        destructive_pattern!(
            "repos-policy-delete",
            r"az\b.*?(?<![\w-])repos\s+policy\s+delete(?![\w-])",
            "az repos policy delete removes a branch policy — the protection on a protected branch.",
            High,
            "repos policy delete removes a branch policy configuration:\n\n\
             - Required reviewers, build validation, comment resolution and\n  \
             merge-strategy constraints stop being enforced immediately\n\
             - Direct pushes to a previously protected branch become possible\n\
             - Removing protection is usually the FIRST step of a destructive\n  \
             sequence, not the destructive step itself\n\n\
             Export the policy before removing it:\n  \
             az repos policy show --id POLICY-ID -o json > policy-backup.json"
        ),
        // ---- az pipelines --------------------------------------------------
        destructive_pattern!(
            "pipelines-delete",
            r"az\b.*?(?<![\w-])pipelines\s+delete(?![\w-])",
            "az pipelines delete removes a pipeline definition and its run history.",
            High,
            "pipelines delete removes an Azure Pipelines definition:\n\n\
             - The definition and its run history are removed\n\
             - Retained builds and their artifacts go with it\n\
             - A YAML pipeline's file survives in the repository; a classic\n  \
             pipeline's definition does not exist anywhere else\n\
             - `--yes` skips the confirmation prompt\n\n\
             Export the definition first:\n  \
             az pipelines show --id ID -o json > pipeline-backup.json"
        ),
        destructive_pattern!(
            "pipelines-folder-delete",
            r"az\b.*?(?<![\w-])pipelines\s+folder\s+delete(?![\w-])",
            "az pipelines folder delete removes a pipeline folder and the pipelines inside it.",
            Medium,
            "pipelines folder delete removes a pipeline folder:\n\n\
             - Pipelines organised under the folder are removed with it\n\
             - There is no per-pipeline confirmation\n\n\
             List the contents first:\n  \
             az pipelines list --folder-path PATH -o table"
        ),
        destructive_pattern!(
            "pipelines-variable-group-delete",
            r"az\b.*?(?<![\w-])pipelines\s+variable-group\s+delete(?![\w-])",
            "az pipelines variable-group delete removes a shared variable group and its secrets.",
            High,
            "pipelines variable-group delete removes a variable group:\n\n\
             - Every pipeline that links the group fails on its next run\n\
             - Secret variables stored in the group are destroyed and cannot be\n  \
             read back from Azure DevOps\n\
             - A group linked to Key Vault loses only the link, not the vault\n\n\
             Export the non-secret values first:\n  \
             az pipelines variable-group show --group-id ID -o json"
        ),
        destructive_pattern!(
            "pipelines-variable-delete",
            r"az\b.*?(?<![\w-])pipelines\s+(?:variable-group\s+)?variable\s+delete(?![\w-])",
            "az pipelines variable delete removes a pipeline or variable-group variable.",
            Medium,
            "pipelines variable delete removes a single variable:\n\n\
             - Runs that read it fail or silently take a default\n\
             - A secret variable's value cannot be read back before deletion,\n  \
             so it is unrecoverable once removed\n\n\
             List the variables first:\n  \
             az pipelines variable list --pipeline-id ID"
        ),
        // ---- az boards -----------------------------------------------------
        destructive_pattern!(
            "boards-work-item-delete",
            r"az\b.*?(?<![\w-])boards\s+work-item\s+delete(?![\w-])",
            "az boards work-item delete removes a work item; with --destroy it is destroyed permanently.",
            High,
            "boards work-item delete removes a work item:\n\n\
             - By default it moves to the project recycle bin and can be restored\n\
             - `--destroy` bypasses the recycle bin and destroys it PERMANENTLY,\n  \
             including its history, links and attachments\n\
             - `--yes` skips the confirmation prompt\n\n\
             Read it first:\n  \
             az boards work-item show --id ID -o json > work-item-backup.json"
        ),
        destructive_pattern!(
            "boards-classification-node-delete",
            r"az\b.*?(?<![\w-])boards\s+(?:area|iteration)\s+project\s+delete(?![\w-])",
            "az boards area/iteration project delete removes a classification node from the project.",
            Medium,
            "boards area/iteration project delete removes a classification node:\n\n\
             - Work items assigned to the node are reassigned to the path given\n  \
             by `--path`, silently moving them out of their sprint or area\n\
             - Child nodes are removed with the parent\n\
             - Team configurations referencing the node are invalidated\n\n\
             See what is assigned first:\n  \
             az boards query --wiql \"SELECT [System.Id] FROM workitems WHERE \
             [System.AreaPath] UNDER 'PATH'\""
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packs::Severity;
    use crate::packs::test_helpers::*;

    /// Every rule fires on its documented invocation, under global `az` flags
    /// too, and is attributed to the rule that actually describes it.
    #[test]
    fn azure_devops_blocks_each_destructive_pattern() {
        let pack = create_pack();
        for (command, pattern) in [
            (
                "az devops project delete --id 00000000-0000-0000-0000-000000000000 --yes",
                "devops-project-delete",
            ),
            ("az devops team delete --id team-id --yes", "devops-team-delete"),
            ("az devops user remove --user user@corp.com --yes", "devops-user-remove"),
            (
                "az devops security group delete --id vssgp.abc --yes",
                "devops-security-group-delete",
            ),
            (
                "az devops security group membership remove --group-id vssgp.abc --member-id aad.def --yes",
                "devops-security-group-membership-remove",
            ),
            (
                "az devops security permission reset-all --id ns --subject u --token tok --yes",
                "devops-security-permission-reset-all",
            ),
            (
                "az devops security permission reset --id ns --subject u --token tok --permission-bit 4",
                "devops-security-permission-reset",
            ),
            (
                "az devops service-endpoint delete --id 00000000-0000-0000-0000-000000000000 --yes",
                "devops-service-endpoint-delete",
            ),
            ("az devops wiki delete --wiki prod.wiki --yes", "devops-wiki-delete"),
            (
                "az devops wiki page delete --path /Runbooks --wiki prod.wiki --yes",
                "devops-wiki-page-delete",
            ),
            (
                "az devops extension uninstall --extension-id ext --publisher-id pub --yes",
                "devops-extension-uninstall",
            ),
            ("az devops logout", "devops-logout"),
            (
                "az devops invoke --area git --resource repositories --http-method DELETE --route-parameters project=p",
                "devops-invoke-delete",
            ),
            (
                "az devops invoke --area policy --resource configurations --http-method PUT --in-file p.json",
                "devops-invoke-write",
            ),
            ("az repos delete --id 00000000-0000-0000-0000-000000000000 --yes", "repos-delete"),
            (
                "az repos ref delete --name heads/main --object-id abc123 --repository prod",
                "repos-ref-delete",
            ),
            ("az repos policy delete --id 7 --yes", "repos-policy-delete"),
            ("az pipelines delete --id 12 --yes", "pipelines-delete"),
            ("az pipelines folder delete --path prod --yes", "pipelines-folder-delete"),
            (
                "az pipelines variable-group delete --group-id 3 --yes",
                "pipelines-variable-group-delete",
            ),
            ("az pipelines variable delete --name TOKEN --pipeline-id 12 --yes", "pipelines-variable-delete"),
            (
                "az pipelines variable-group variable delete --group-id 3 --name TOKEN --yes",
                "pipelines-variable-delete",
            ),
            ("az boards work-item delete --id 42 --destroy --yes", "boards-work-item-delete"),
            (
                "az boards area project delete --path \\\\Prod\\\\Legacy --yes",
                "boards-classification-node-delete",
            ),
            (
                "az boards iteration project delete --path \\\\Prod\\\\Sprint1 --yes",
                "boards-classification-node-delete",
            ),
        ] {
            assert_no_safe_match(&pack, command);
            assert_blocks_with_pattern(&pack, command, pattern);

            // Azure CLI global flags sit between `az` and the command group.
            let with_globals =
                command.replacen("az ", "az --only-show-errors --output json ", 1);
            assert_blocks_with_pattern(&pack, &with_globals, pattern);

            // `--help` prints usage and exits before any REST call.
            assert_allows(&pack, &format!("{command} --help"));
            assert_allows(&pack, &format!("{command} -h"));
        }
    }

    #[test]
    fn azure_devops_severities_match_blast_radius() {
        let pack = create_pack();
        assert_blocks_with_severity(
            &pack,
            "az devops project delete --id p --yes",
            Severity::Critical,
        );
        assert_blocks_with_severity(&pack, "az repos delete --id r --yes", Severity::Critical);
        assert_blocks_with_severity(&pack, "az repos policy delete --id 7 --yes", Severity::High);
        assert_blocks_with_severity(&pack, "az pipelines delete --id 1 --yes", Severity::High);
        assert_blocks_with_severity(
            &pack,
            "az pipelines folder delete --path p --yes",
            Severity::Medium,
        );
        assert_blocks_with_severity(
            &pack,
            "az boards work-item delete --id 1 --yes",
            Severity::High,
        );
    }

    /// Read-only and ordinary development commands must not be blocked, and a
    /// hyphenated sibling subcommand must never inherit a rule (#380 shape).
    #[test]
    fn azure_devops_allows_read_only_and_routine_workflow() {
        let pack = create_pack();
        for command in [
            // Organization
            "az devops project list",
            "az devops project show --project prod",
            "az devops team list --project prod",
            "az devops team list-member --team dev --project prod",
            "az devops user list",
            "az devops user show --user user@corp.com",
            "az devops user add --email-id user@corp.com --license-type express",
            "az devops security group list --project prod",
            "az devops security group membership list --id vssgp.abc",
            "az devops security permission list --id ns --subject u",
            "az devops security permission namespace list",
            "az devops security permission update --id ns --subject u --token t --allow-bit 4",
            "az devops service-endpoint list --project prod",
            "az devops extension list",
            "az devops extension search --search-query terraform",
            "az devops extension install --extension-id ext --publisher-id pub",
            "az devops wiki list --project prod",
            "az devops wiki page show --path /Home --wiki prod.wiki",
            "az devops configure --list",
            "az devops login --org https://dev.azure.com/acme",
            "az devops invoke --area wiki --resource wikis --route-parameters project=prod",
            "az devops invoke --area wiki --resource wikis --http-method GET",
            "az devops admin banner list",
            // Repos
            "az repos list --project prod",
            "az repos show --repository prod",
            "az repos create --name new-service",
            "az repos update --repository prod --default-branch main",
            "az repos import create --git-source-url https://github.com/acme/x --repository prod",
            "az repos ref list --repository prod",
            "az repos ref lock --name heads/main --repository prod",
            "az repos policy list --project prod",
            "az repos pr create --source-branch feature --target-branch main",
            "az repos pr list --status active",
            "az repos pr checkout --id 12",
            // Pipelines
            "az pipelines list --project prod",
            "az pipelines show --id 12",
            "az pipelines run --name nightly",
            "az pipelines runs list --project prod",
            "az pipelines runs artifact download --run-id 5 --artifact-name drop --path .",
            "az pipelines variable list --pipeline-id 12",
            "az pipelines variable-group list --project prod",
            "az pipelines agent list --pool-id 1",
            "az pipelines build list --project prod",
            // Boards
            "az boards query --wiql \"SELECT [System.Id] FROM workitems\"",
            "az boards work-item show --id 42",
            "az boards work-item create --title Bug --type Bug",
            "az boards work-item update --id 42 --state Active",
            "az boards area project list --project prod",
            "az boards iteration project list --project prod",
            "az boards iteration team list --team dev",
            // Artifacts: the whole documented group, neither half destructive
            "az artifacts universal download --feed f --name pkg --version 1.0.0 --path .",
            "az artifacts universal publish --feed f --name pkg --version 1.0.0 --path .",
        ] {
            assert_allows(&pack, command);
        }
    }

    /// A `--help` that is only quoted argument TEXT is not the help flag, and
    /// a redirection target named `--help` is not one either.
    #[test]
    fn azure_devops_help_carve_out_is_exact() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "az repos delete --id 'r --help' --yes",
            "repos-delete",
        );
        assert_blocks_with_pattern(
            &pack,
            "az repos delete --id r --yes > --help",
            "repos-delete",
        );
        assert_no_safe_match(&pack, "az repos delete --id 'r --help' --yes");
    }

    /// `reset-all` is a different command from `reset`, and a hyphenated
    /// sibling must not inherit a rule (#380).
    #[test]
    fn azure_devops_verbs_do_not_leak_into_hyphenated_siblings() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "az devops security permission reset-all --id ns --subject u --token t --yes",
            "devops-security-permission-reset-all",
        );
        assert_blocks_with_pattern(
            &pack,
            "az devops security permission reset --id ns --subject u --token t --permission-bit 1",
            "devops-security-permission-reset",
        );
        // Hypothetical hyphenated siblings must not be claimed by the plain
        // verb rules: the guards are what make future CLI growth safe.
        for command in [
            "az repos delete-mirror --id r",
            "az pipelines delete-preview --id 1",
            "az devops project delete-draft --id p",
            "az boards work-item delete-link --id 1",
        ] {
            assert_allows(&pack, command);
        }
    }

    #[test]
    fn azure_devops_unrelated_commands_no_match() {
        let pack = create_pack();
        assert_no_match(&pack, "git status");
        assert_no_match(&pack, "gh repo delete acme/widgets");
        assert_no_match(&pack, "echo hello");
    }
}
