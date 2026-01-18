//! MCP server mode for direct agent integration.
//!
//! This exposes dcg as an MCP tool server over stdio, providing structured
//! checks without shell-hook overhead.

use crate::config::Config;
use crate::evaluator::{EvaluationDecision, evaluate_command};
use crate::packs::REGISTRY;
use crate::scan::{
    ScanEvalContext, ScanFailOn, ScanFormat, ScanOptions, ScanRedactMode, scan_paths,
};
use async_trait::async_trait;
use rust_mcp_sdk::mcp_server::{
    McpServerOptions, ServerHandler, ToMcpServerHandler, server_runtime,
};
use rust_mcp_sdk::schema::schema_utils::CallToolError;
use rust_mcp_sdk::schema::{
    CallToolRequestParams, CallToolResult, Implementation, InitializeResult, ListToolsResult,
    PaginatedRequestParams, ProtocolVersion, RpcError, ServerCapabilities, ServerCapabilitiesTools,
    TextContent, Tool, ToolInputSchema,
};
use rust_mcp_sdk::{McpServer, StdioTransport, TransportOptions};
use serde::Serialize;
use serde_json::{Map, Value};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Debug)]
pub struct DcgMcpServer {
    server_info: InitializeResult,
    config: Config,
    scan_ctx: ScanEvalContext,
}

#[derive(Serialize)]
struct AllowlistInfo {
    layer: String,
    reason: String,
}

#[derive(Serialize)]
struct CheckCommandResponse {
    allowed: bool,
    decision: String,
    mode: Option<String>,
    skipped_due_to_budget: bool,
    reason: Option<String>,
    rule_id: Option<String>,
    pack_id: Option<String>,
    pattern_name: Option<String>,
    severity: Option<String>,
    explanation: Option<String>,
    matched_text_preview: Option<String>,
    allowlist: Option<AllowlistInfo>,
}

#[derive(Serialize)]
struct ExplainPatternResponse {
    rule_id: String,
    pack_id: String,
    pattern_name: String,
    severity: String,
    reason: String,
    explanation: String,
}

impl DcgMcpServer {
    #[must_use]
    pub fn new() -> Self {
        let config = Config::load();
        let scan_ctx = ScanEvalContext::from_config(&config);
        let server_info = InitializeResult {
            protocol_version: ProtocolVersion::V2025_11_25.into(),
            server_info: Implementation {
                description: Some(
                    "Destructive Command Guard MCP server for command safety checks.".to_string(),
                ),
                icons: Vec::new(),
                name: "dcg".to_string(),
                title: Some("Destructive Command Guard".to_string()),
                version: env!("CARGO_PKG_VERSION").to_string(),
                website_url: None,
            },
            capabilities: ServerCapabilities {
                completions: None,
                experimental: None,
                logging: None,
                prompts: None,
                resources: None,
                tasks: None,
                tools: Some(ServerCapabilitiesTools {
                    list_changed: Some(false),
                }),
            },
            instructions: Some(
                "Destructive Command Guard MCP server. Tools: check_command, scan_file, explain_pattern."
                    .to_string(),
            ),
            meta: None,
        };

        Self {
            server_info,
            config,
            scan_ctx,
        }
    }

    const fn default_scan_options() -> ScanOptions {
        ScanOptions {
            format: ScanFormat::Pretty,
            fail_on: ScanFailOn::Error,
            max_file_size_bytes: 1_048_576,
            max_findings: 100,
            redact: ScanRedactMode::None,
            truncate: 200,
        }
    }

    fn tool_input_schema(
        required: &[&str],
        props: Vec<(&str, Map<String, Value>)>,
    ) -> ToolInputSchema {
        let mut properties = HashMap::new();
        for (name, schema) in props {
            properties.insert(name.to_string(), schema);
        }
        ToolInputSchema::new(
            required.iter().map(|s| (*s).to_string()).collect(),
            Some(properties),
            None,
        )
    }

    fn string_schema(description: &str) -> Map<String, Value> {
        let mut map = Map::new();
        map.insert("type".to_string(), Value::String("string".to_string()));
        map.insert(
            "description".to_string(),
            Value::String(description.to_string()),
        );
        map
    }

    fn tool(name: &str, description: &str, schema: ToolInputSchema) -> Tool {
        Tool {
            name: name.to_string(),
            description: Some(description.to_string()),
            execution: None,
            icons: Vec::new(),
            input_schema: schema,
            title: None,
            annotations: None,
            meta: None,
            output_schema: None,
        }
    }

    fn tool_result_json<T: Serialize>(value: &T) -> Result<CallToolResult, CallToolError> {
        let json = serde_json::to_string_pretty(value).map_err(CallToolError::new)?;
        Ok(CallToolResult::text_content(vec![TextContent::from(json)]))
    }

    fn call_tool_error(message: impl Into<String>) -> CallToolError {
        CallToolError::new(std::io::Error::other(message.into()))
    }

    fn string_arg(args: Option<&Map<String, Value>>, key: &str) -> Result<String, CallToolError> {
        let args = args.ok_or_else(|| {
            Self::call_tool_error(format!("Missing arguments for tool (expected '{key}')"))
        })?;
        let value = args.get(key).and_then(|v| v.as_str()).ok_or_else(|| {
            Self::call_tool_error(format!("Missing or invalid '{key}' parameter"))
        })?;
        Ok(value.to_string())
    }

    fn rule_id_from_match(pack_id: Option<&str>, pattern_name: Option<&str>) -> Option<String> {
        match (pack_id, pattern_name) {
            (Some(pack), Some(name)) => Some(format!("{pack}:{name}")),
            _ => None,
        }
    }

    fn check_command(&self, command: &str) -> CheckCommandResponse {
        let result = evaluate_command(
            command,
            &self.config,
            &self.scan_ctx.enabled_keywords,
            &self.scan_ctx.compiled_overrides,
            &self.scan_ctx.allowlists,
        );

        let mode = result.effective_mode.map(|m| m.label().to_string());
        let allowed = result
            .effective_mode
            .map_or(result.decision != EvaluationDecision::Deny, |m| !m.blocks());

        let mut response = CheckCommandResponse {
            allowed,
            decision: match result.decision {
                EvaluationDecision::Allow => "allow".to_string(),
                EvaluationDecision::Deny => "deny".to_string(),
            },
            mode,
            skipped_due_to_budget: result.skipped_due_to_budget,
            reason: None,
            rule_id: None,
            pack_id: None,
            pattern_name: None,
            severity: None,
            explanation: None,
            matched_text_preview: None,
            allowlist: None,
        };

        if let Some(override_) = result.allowlist_override.as_ref() {
            response.allowlist = Some(AllowlistInfo {
                layer: override_.layer.label().to_string(),
                reason: override_.reason.clone(),
            });
        }

        let match_info = result
            .pattern_info
            .as_ref()
            .or_else(|| result.allowlist_override.as_ref().map(|o| &o.matched));

        if let Some(info) = match_info {
            response.reason = Some(info.reason.clone());
            response.rule_id =
                Self::rule_id_from_match(info.pack_id.as_deref(), info.pattern_name.as_deref());
            response.pack_id.clone_from(&info.pack_id);
            response.pattern_name.clone_from(&info.pattern_name);
            response.severity = info.severity.map(|s| s.label().to_string());
            response.explanation.clone_from(&info.explanation);
            response
                .matched_text_preview
                .clone_from(&info.matched_text_preview);
        }

        response
    }

    fn explain_pattern(rule_id: &str) -> Result<ExplainPatternResponse, CallToolError> {
        let (pack_id, pattern_name) = rule_id
            .split_once(':')
            .ok_or_else(|| Self::call_tool_error("rule_id must be in 'pack:pattern' format"))?;

        let pack = REGISTRY
            .get(pack_id)
            .ok_or_else(|| Self::call_tool_error(format!("Unknown pack '{pack_id}'")))?;

        let pattern = pack
            .destructive_patterns
            .iter()
            .find(|p| p.name == Some(pattern_name))
            .ok_or_else(|| {
                Self::call_tool_error(format!(
                    "Pattern '{pattern_name}' not found in pack '{pack_id}'"
                ))
            })?;

        let reason = pattern.reason.to_string();
        let explanation = pattern.explanation.unwrap_or(pattern.reason).to_string();

        Ok(ExplainPatternResponse {
            rule_id: rule_id.to_string(),
            pack_id: pack_id.to_string(),
            pattern_name: pattern_name.to_string(),
            severity: pattern.severity.label().to_string(),
            reason,
            explanation,
        })
    }
}

impl Default for DcgMcpServer {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ServerHandler for DcgMcpServer {
    async fn handle_list_tools_request(
        &self,
        _params: Option<PaginatedRequestParams>,
        _runtime: Arc<dyn McpServer>,
    ) -> Result<ListToolsResult, RpcError> {
        let tools = vec![
            Self::tool(
                "check_command",
                "Evaluate a command using dcg policy",
                Self::tool_input_schema(
                    &["command"],
                    vec![("command", Self::string_schema("Command to evaluate"))],
                ),
            ),
            Self::tool(
                "scan_file",
                "Scan a file or directory for destructive commands",
                Self::tool_input_schema(
                    &["path"],
                    vec![(
                        "path",
                        Self::string_schema("File or directory path to scan"),
                    )],
                ),
            ),
            Self::tool(
                "explain_pattern",
                "Explain a dcg rule by rule_id",
                Self::tool_input_schema(
                    &["rule_id"],
                    vec![(
                        "rule_id",
                        Self::string_schema("Rule id in the form 'pack:pattern'"),
                    )],
                ),
            ),
        ];

        Ok(ListToolsResult {
            tools,
            next_cursor: None,
            meta: None,
        })
    }

    async fn handle_call_tool_request(
        &self,
        params: CallToolRequestParams,
        _runtime: Arc<dyn McpServer>,
    ) -> Result<CallToolResult, CallToolError> {
        match params.name.as_str() {
            "check_command" => {
                let command = Self::string_arg(params.arguments.as_ref(), "command")?;
                let response = self.check_command(&command);
                Self::tool_result_json(&response)
            }
            "scan_file" => {
                let path = Self::string_arg(params.arguments.as_ref(), "path")?;
                let path_buf = PathBuf::from(path);
                let options = Self::default_scan_options();
                let include: Vec<String> = Vec::new();
                let exclude: Vec<String> = Vec::new();
                let report = scan_paths(
                    &[path_buf],
                    &options,
                    &self.config,
                    &self.scan_ctx,
                    &include,
                    &exclude,
                    None,
                )
                .map_err(Self::call_tool_error)?;
                Self::tool_result_json(&report)
            }
            "explain_pattern" => {
                let rule_id = Self::string_arg(params.arguments.as_ref(), "rule_id")?;
                let response = Self::explain_pattern(&rule_id)?;
                Self::tool_result_json(&response)
            }
            other => Err(Self::call_tool_error(format!("Unknown tool '{other}'"))),
        }
    }
}

/// # Errors
///
/// Returns an error when the MCP server fails to initialize or run.
pub async fn run_mcp_server_async() -> Result<(), Box<dyn std::error::Error>> {
    let handler = DcgMcpServer::new();
    let server_details = handler.server_info.clone();
    let transport = StdioTransport::new(TransportOptions::default())?;
    let server = server_runtime::create_server(McpServerOptions {
        transport,
        handler: handler.to_mcp_server_handler(),
        server_details,
        task_store: None,
        client_task_store: None,
    });
    server.start().await?;
    Ok(())
}

/// # Errors
///
/// Returns an error when the async runtime or MCP server fails to start.
pub fn run_mcp_server() -> Result<(), Box<dyn std::error::Error>> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(run_mcp_server_async())
}
