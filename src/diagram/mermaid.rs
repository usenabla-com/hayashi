//! Mermaid architecture diagram generation with LLM assistance
//! Converts infrastructure resource graphs into human-friendly Mermaid architecture diagrams
//! with trust zone grouping for FedRAMP/NIST 800-53 compliance

use crate::diagram::graph::{ResourceGraph, ResourceNode};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;

/// Mermaid diagram generator using Cloudflare Workers AI
pub struct MermaidGenerator {
    account_id: String,
    api_token: String,
    model: String,
}

impl MermaidGenerator {
    /// Create a new generator with Cloudflare Workers AI
    pub fn new() -> Result<Self> {
        let account_id = std::env::var("CLOUDFLARE_ACCOUNT_ID")
            .context("CLOUDFLARE_ACCOUNT_ID environment variable required")?;
        let api_token = std::env::var("CLOUDFLARE_API_TOKEN")
            .context("CLOUDFLARE_API_TOKEN environment variable required")?;

        Ok(Self {
            account_id,
            api_token,
            model: "@cf/openai/gpt-oss-120b".to_string(),
        })
    }

    /// Create a new generator with custom model
    pub fn with_model(model: String) -> Result<Self> {
        let account_id = std::env::var("CLOUDFLARE_ACCOUNT_ID")
            .context("CLOUDFLARE_ACCOUNT_ID environment variable required")?;
        let api_token = std::env::var("CLOUDFLARE_API_TOKEN")
            .context("CLOUDFLARE_API_TOKEN environment variable required")?;

        Ok(Self {
            account_id,
            api_token,
            model,
        })
    }

    /// Create a new generator with custom model and API key
    pub fn with_model_and_key(model: String, api_key: String) -> Result<Self> {
        let account_id = std::env::var("CLOUDFLARE_ACCOUNT_ID")
            .context("CLOUDFLARE_ACCOUNT_ID environment variable required")?;

        Ok(Self {
            account_id,
            api_token: api_key,
            model,
        })
    }

    /// Generate a Mermaid architecture diagram from a resource graph
    pub async fn generate_architecture_diagram(
        &self,
        graph: &ResourceGraph,
        title: &str,
    ) -> Result<MermaidDiagram> {
        let summary = graph.summary();

        // Build the base diagram structure with trust zone hierarchy
        let mut diagram_builder = MermaidArchitectureBuilder::new(title);

        // Build trust zone hierarchy
        let trust_zones = self.build_trust_zone_hierarchy(&graph.nodes);

        // Add hierarchical groups and nodes
        self.add_trust_zones_to_diagram(&mut diagram_builder, &trust_zones, &graph.nodes);

        // Add edges with enhanced metadata
        for edge in &graph.edges {
            let edge_metadata = self.analyze_edge(&edge.from, &edge.to, &edge.relationship, &graph.nodes);
            diagram_builder.add_connection_with_metadata(
                &edge.from,
                &edge.to,
                &edge_metadata
            );
        }

        let raw_diagram = diagram_builder.build();

        // Enhance the diagram with LLM-generated descriptions
        let diagram_content = self.enhance_diagram_with_llm(&raw_diagram, graph).await?;

        Ok(MermaidDiagram {
            content: diagram_content,
            node_count: summary.node_count,
            edge_count: summary.edge_count,
            metadata: DiagramMetadata {
                title: title.to_string(),
                generated_at: chrono::Utc::now().to_rfc3339(),
                categories: summary.categories,
                zones: summary.zones,
            },
        })
    }

    /// Enhance diagram with LLM-generated descriptions using Cloudflare Workers AI
    async fn enhance_diagram_with_llm(
        &self,
        base_diagram: &str,
        graph: &ResourceGraph,
    ) -> Result<String> {
        let graph_json = serde_json::to_string_pretty(graph)
            .context("Failed to serialize graph")?;

        let prompt = format!(
            r#"You are an expert at creating AWS FedRAMP compliance architecture diagrams using Mermaid flowchart syntax with custom AWS icons.

CRITICAL FEDRAMP COMPLIANCE REQUIREMENTS:
1. **Authorization Boundary**: Draw a dashed box subgraph labeled "FedRAMP Authorization Boundary" containing all customer-managed resources
2. **Trust Zones**: Separate Public, Application, and Data tiers with clear boundaries
3. **Encryption Annotations**: Label encrypted resources with "🔒 EBS-CMK", "🔒 KMS", "🔒 TLS 1.2+"
4. **Data Flow**: Show explicit directional arrows for traffic flow (Internet → IGW → Web → App → DB)
5. **Required FedRAMP Services**: Include Config, GuardDuty, CloudTrail, VPC Flow Logs, KMS
6. **Control Labels**: Add NIST 800-53 control references (SC-7, AU-2, CM-2, etc.)

MERMAID FLOWCHART SYNTAX WITH AWS ICONS:
```
flowchart TB
    %% Subgraphs for boundaries
    subgraph boundary["<b>FedRAMP Authorization Boundary</b>"]
        direction TB

        subgraph vpc["<b>VPC: Production (10.0.0.0/16)</b>"]
            direction TB

            subgraph public["<b>Public Tier - SC-7</b>"]
                igw[["<img src='https://cdn.prod.website-files.com/5f05d5858fab461d0d08eaeb/635a1c060b1a32823c9159d0_internet_gateway_light.svg' width='40'/><br/>Internet Gateway"]]
                nat[["<img src='https://cdn.prod.website-files.com/5f05d5858fab461d0d08eaeb/6358cec281674a47f95c499b_nat_gateway_light.svg' width='40'/><br/>NAT Gateway"]]
            end

            subgraph app["<b>Application Tier - Private</b>"]
                web[["<img src='https://icon.icepanel.io/AWS/svg/Compute/EC2.svg' width='40'/><br/>Web Server<br/>🔒 EBS-CMK"]]
                app_server[["<img src='https://icon.icepanel.io/AWS/svg/Compute/EC2.svg' width='40'/><br/>App Server<br/>🔒 EBS-CMK"]]
            end

            subgraph data["<b>Data Tier - Encrypted</b>"]
                rds[["<img src='https://icon.icepanel.io/AWS/svg/Database/RDS.svg' width='40'/><br/>PostgreSQL RDS<br/>🔒 KMS Encrypted"]]
                s3[["<img src='https://icon.icepanel.io/AWS/svg/Storage/Simple-Storage-Service.svg' width='40'/><br/>S3 Backups<br/>🔒 KMS + Versioning"]]
            end
        end

        subgraph security["<b>Security & Compliance - AC-6, AU-2</b>"]
            kms[["<img src='https://icon.icepanel.io/AWS/svg/Security-Identity-Compliance/Key-Management-Service.svg' width='40'/><br/>KMS CMK"]]
            cloudtrail[["<img src='https://icon.icepanel.io/AWS/svg/Management-Governance/CloudTrail.svg' width='40'/><br/>CloudTrail<br/>CM-2"]]
            guardduty[["<img src='https://icon.icepanel.io/AWS/svg/Security-Identity-Compliance/GuardDuty.svg' width='40'/><br/>GuardDuty<br/>IR-4"]]
            config[["<img src='https://icon.icepanel.io/AWS/svg/Management-Governance/Config.svg' width='40'/><br/>AWS Config<br/>CM-6"]]
        end
    end

    internet["☁️ Internet"] --> igw
    igw -->|"HTTPS 443<br/>TLS 1.2+"| web
    web --> app_server
    app_server -->|"PostgreSQL 5432<br/>Encrypted"| rds
    rds -.->|"Automated Backups"| s3

    kms -.->|"Encrypts"| rds
    kms -.->|"Encrypts"| s3
    kms -.->|"Encrypts"| web
    cloudtrail -.->|"Audit Logs"| s3

    style boundary fill:#e3f2fd,stroke:#1976d2,stroke-width:4px,stroke-dasharray: 10 5
    style security fill:#fff3e0,stroke:#f57c00,stroke-width:2px
    style data fill:#fce4ec,stroke:#c2185b,stroke-width:2px
```

RULES FOR FEDRAMP DIAGRAMS:
- Use `flowchart TB` (top-to-bottom) or `LR` (left-to-right)
- Use `subgraph` for boundaries with `<b>` tags for bold labels
- Use `[[" "]]` for nodes with images and multiline labels
- Add encryption emoji 🔒 next to encrypted resources
- Add NIST control references (SC-7, AU-2, etc.) in subgraph labels
- Use `-->` for data flow, `-.->` for audit/backup flows
- Add `style` at the end to color-code trust zones
- Include AWS service icons via img tags or icon references
- Add a linebreak between icon and label in nodes

Here is the base diagram to enhance:
```
{}
```

Infrastructure data:
```json
{}
```

Output ONLY valid Mermaid architecture-beta syntax following the AWS ABD style above. Use proper directional arrows (-->, <--, -.->), AWS icon names, but NO connection labels. No markdown blocks, no explanations."#,
            base_diagram, graph_json
        );

        // Call Cloudflare Workers AI REST API
        let url = format!(
            "https://api.cloudflare.com/client/v4/accounts/{}/ai/run/{}",
            self.account_id, self.model
        );

        let client = reqwest::Client::new();
        let response = client
            .post(&url)
            .header("Content-Type", "application/json")
            .header("Authorization", format!("Bearer {}", self.api_token))
            .json(&json!({
                "input": prompt
            }))
            .send()
            .await
            .context("Failed to call Cloudflare Workers AI")?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            anyhow::bail!(
                "Cloudflare Workers AI request failed with status {}: {}",
                status,
                error_text
            );
        }

        // First get the response as text to debug
        let response_text = response.text().await
            .context("Failed to read Workers AI response body")?;

        tracing::debug!("Workers AI raw response: {}", response_text);

        // Try to parse as JSON Value first to inspect structure
        let response_json: serde_json::Value = serde_json::from_str(&response_text)
            .context("Failed to parse Workers AI response as JSON")?;

        // Workers AI text generation models return different formats:
        // 1. { "result": { "response": "..." }, "success": true }
        // 2. { "result": "...", "success": true }
        // 3. { "result": { "output": [{"type": "reasoning", ...}, {"type": "message", "content": [{"text": "..."}]}] }, "success": true }

        let generated_text = if let Some(result) = response_json.get("result") {
            // Try format 3: output array with message content
            if let Some(output) = result.get("output").and_then(|v| v.as_array()) {
                // Find the message output (usually the last item or type="message")
                let message_output = output.iter().rev().find(|item| {
                    item.get("type").and_then(|t| t.as_str()) == Some("message")
                }).or_else(|| output.last());

                if let Some(msg) = message_output {
                    if let Some(content_array) = msg.get("content").and_then(|c| c.as_array()) {
                        if let Some(text) = content_array.first()
                            .and_then(|item| item.get("text"))
                            .and_then(|t| t.as_str()) {
                            text.to_string()
                        } else {
                            anyhow::bail!(
                                "Workers AI output array found but no text in content. Got: {}",
                                serde_json::to_string_pretty(&response_json).unwrap_or_default()
                            );
                        }
                    } else {
                        anyhow::bail!(
                            "Workers AI output array found but no content array. Got: {}",
                            serde_json::to_string_pretty(&response_json).unwrap_or_default()
                        );
                    }
                } else {
                    anyhow::bail!(
                        "Workers AI output array found but no message output. Got: {}",
                        serde_json::to_string_pretty(&response_json).unwrap_or_default()
                    );
                }
            } else if let Some(response_str) = result.get("response").and_then(|v| v.as_str()) {
                // Format 1: { result: { response: "..." } }
                response_str.to_string()
            } else if let Some(response_str) = result.as_str() {
                // Format 2: { result: "..." }
                response_str.to_string()
            } else {
                anyhow::bail!(
                    "Unexpected Workers AI response format. Expected result.response, result as string, or result.output array. Got: {}",
                    serde_json::to_string_pretty(&response_json).unwrap_or_default()
                );
            }
        } else {
            anyhow::bail!(
                "Workers AI response missing 'result' field. Full response: {}",
                serde_json::to_string_pretty(&response_json).unwrap_or_default()
            );
        };

        // Check success flag if present
        if let Some(success) = response_json.get("success").and_then(|v| v.as_bool()) {
            if !success {
                anyhow::bail!("Workers AI request was not successful");
            }
        }

        // Post-process the generated text to ensure valid syntax
        let cleaned_text = self.clean_generated_diagram(&generated_text);

        Ok(cleaned_text)
    }

    /// Clean and validate generated diagram syntax
    fn clean_generated_diagram(&self, text: &str) -> String {
        let mut cleaned = text.trim().to_string();

        // Remove markdown code blocks if present
        if cleaned.starts_with("```") {
            cleaned = cleaned
                .lines()
                .skip(1) // Skip opening ```
                .take_while(|line| !line.trim().starts_with("```"))
                .collect::<Vec<_>>()
                .join("\n");
        }

        // Remove any lines that start with 'mermaid' or 'architecture'
        if cleaned.lines().next().map(|l| l.trim()) == Some("mermaid") {
            cleaned = cleaned.lines().skip(1).collect::<Vec<_>>().join("\n");
        }

        cleaned.trim().to_string()
    }

    /// Build trust zone hierarchy for FedRAMP/NIST 800-53 compliance
    fn build_trust_zone_hierarchy(&self, nodes: &[ResourceNode]) -> TrustZoneHierarchy {
        let mut hierarchy = TrustZoneHierarchy::default();

        // Identify VPCs, subnets, and their relationships
        let subnets: Vec<_> = nodes.iter().filter(|n| n.resource_type == "aws_subnet").collect();
        let igws: Vec<_> = nodes.iter().filter(|n| n.resource_type == "aws_internet_gateway").collect();

        // Build subnet tier classifications
        let subnet_tiers = self.classify_subnet_tiers(&subnets, &igws, nodes);

        // Categorize all resources
        for node in nodes {
            let category = self.categorize_resource(&node.resource_type, node);

            match category {
                ResourceCategory::Identity => {
                    hierarchy.identity_plane.push(node.clone());
                }
                ResourceCategory::KeyManagement => {
                    hierarchy.key_plane.push(node.clone());
                }
                ResourceCategory::AuditMonitoring => {
                    hierarchy.audit_plane.push(node.clone());
                }
                ResourceCategory::NetworkBoundary => {
                    // Group by VPC
                    let vpc_id = self.get_vpc_id(node);
                    hierarchy.network_boundaries.entry(vpc_id.clone())
                        .or_insert_with(|| NetworkBoundary::new(&vpc_id))
                        .boundary_resources.push(node.clone());
                }
                ResourceCategory::Compute | ResourceCategory::DataStore => {
                    // Group by subnet tier within VPC
                    let subnet_id = self.get_subnet_id(node);
                    if let Some(tier) = subnet_tiers.get(&subnet_id) {
                        let vpc_id = self.get_vpc_id_from_subnet(&subnet_id, &subnets);
                        hierarchy.network_boundaries.entry(vpc_id.clone())
                            .or_insert_with(|| NetworkBoundary::new(&vpc_id))
                            .tiers.entry(tier.clone())
                            .or_insert_with(Vec::new)
                            .push(node.clone());
                    }
                }
                ResourceCategory::External => {
                    hierarchy.external_interfaces.push(node.clone());
                }
            }
        }

        hierarchy.subnet_tiers = subnet_tiers;
        hierarchy
    }

    /// Classify subnets into tiers (public, private-app, private-db, mgmt)
    fn classify_subnet_tiers(
        &self,
        subnets: &[&ResourceNode],
        _igws: &[&ResourceNode],
        all_nodes: &[ResourceNode],
    ) -> HashMap<String, SubnetTier> {
        let mut tiers = HashMap::new();

        for subnet in subnets {
            let subnet_id = subnet.attributes.get("id")
                .and_then(|v| v.as_str())
                .unwrap_or(&subnet.id);

            // Check tags first
            if let Some(tier_tag) = subnet.attributes.get("tags")
                .and_then(|v| v.as_object())
                .and_then(|tags| tags.get("Tier"))
                .and_then(|v| v.as_str()) {
                let tier = match tier_tag.to_lowercase().as_str() {
                    "public" => SubnetTier::Public,
                    "app" | "application" => SubnetTier::PrivateApp,
                    "db" | "database" | "data" => SubnetTier::PrivateDb,
                    "mgmt" | "management" => SubnetTier::Management,
                    _ => SubnetTier::Other(tier_tag.to_string()),
                };
                tiers.insert(subnet_id.to_string(), tier);
                continue;
            }

            // Check Type tag
            if let Some(type_tag) = subnet.attributes.get("tags")
                .and_then(|v| v.as_object())
                .and_then(|tags| tags.get("Type"))
                .and_then(|v| v.as_str()) {
                let tier = match type_tag.to_lowercase().as_str() {
                    "public" => SubnetTier::Public,
                    "private" => {
                        // Further classify based on what's in the subnet
                        self.infer_private_tier(subnet_id, all_nodes)
                    }
                    "database" => SubnetTier::PrivateDb,
                    _ => SubnetTier::Other(type_tag.to_string()),
                };
                tiers.insert(subnet_id.to_string(), tier);
                continue;
            }

            // Infer from map_public_ip_on_launch
            if let Some(public_ip) = subnet.attributes.get("map_public_ip_on_launch")
                .and_then(|v| v.as_bool()) {
                if public_ip {
                    tiers.insert(subnet_id.to_string(), SubnetTier::Public);
                    continue;
                }
            }

            // Infer from resources in the subnet
            let tier = self.infer_private_tier(subnet_id, all_nodes);
            tiers.insert(subnet_id.to_string(), tier);
        }

        tiers
    }

    /// Infer private subnet tier from resources
    fn infer_private_tier(&self, subnet_id: &str, nodes: &[ResourceNode]) -> SubnetTier {
        let resources_in_subnet: Vec<_> = nodes.iter()
            .filter(|n| {
                n.attributes.get("subnet_id")
                    .and_then(|v| v.as_str())
                    .map(|s| s == subnet_id)
                    .unwrap_or(false)
            })
            .collect();

        // Check for database resources
        for node in &resources_in_subnet {
            if matches!(node.resource_type.as_str(),
                "aws_db_instance" | "aws_rds_cluster" | "aws_elasticache_cluster" |
                "aws_docdb_cluster" | "aws_neptune_cluster") {
                return SubnetTier::PrivateDb;
            }
        }

        // Check for compute resources
        for node in &resources_in_subnet {
            if matches!(node.resource_type.as_str(),
                "aws_instance" | "aws_ecs_service" | "aws_eks_node_group" | "aws_autoscaling_group") {
                return SubnetTier::PrivateApp;
            }
        }

        // Check for management resources
        for node in &resources_in_subnet {
            if matches!(node.resource_type.as_str(),
                "aws_vpc_endpoint" | "aws_vpn_gateway" | "aws_dx_gateway") {
                return SubnetTier::Management;
            }
        }

        SubnetTier::PrivateApp
    }

    /// Add trust zones to diagram builder with AWS ABD-style grouping
    fn add_trust_zones_to_diagram(
        &self,
        builder: &mut MermaidArchitectureBuilder,
        zones: &TrustZoneHierarchy,
        nodes: &[ResourceNode],
    ) {
        // 1. Add AWS Cloud boundary first (top-level container)
        builder.add_group("aws_cloud", "AWS Cloud");

        // 2. Add Shared Security Services (positioned outside VPCs in AWS style)
        if !zones.identity_plane.is_empty() || !zones.key_plane.is_empty() || !zones.audit_plane.is_empty() {
            builder.add_group("security_services", "Security & Compliance Services");

            if !zones.identity_plane.is_empty() {
                for node in &zones.identity_plane {
                    let icon = self.get_icon_for_resource(&node.resource_type);
                    let label = self.format_node_label(node);
                    builder.add_service(&node.id, &label, "security_services", &icon);
                }
            }

            if !zones.key_plane.is_empty() {
                for node in &zones.key_plane {
                    let icon = self.get_icon_for_resource(&node.resource_type);
                    let label = self.format_node_label(node);
                    builder.add_service(&node.id, &label, "security_services", &icon);
                }
            }

            if !zones.audit_plane.is_empty() {
                for node in &zones.audit_plane {
                    let icon = self.get_icon_for_resource(&node.resource_type);
                    let label = self.format_node_label(node);
                    builder.add_service(&node.id, &label, "security_services", &icon);
                }
            }
        }

        // 3. Add Network Boundaries (VPCs) with region context
        for (vpc_id, boundary) in &zones.network_boundaries {
            let vpc_node = nodes.iter().find(|n|
                n.resource_type == "aws_vpc" &&
                n.attributes.get("id").and_then(|v| v.as_str()).unwrap_or(&n.id) == vpc_id
            );

            let vpc_label = vpc_node
                .and_then(|n| n.attributes.get("tags")
                    .and_then(|v| v.as_object())
                    .and_then(|tags| tags.get("Name"))
                    .and_then(|v| v.as_str()))
                .unwrap_or(vpc_id);

            // Add VPC group
            let vpc_group_name = format!("VPC: {}", vpc_label);
            builder.add_group(vpc_id, &vpc_group_name);

            // Add boundary resources (IGW, NAT, etc.) directly in VPC
            if !boundary.boundary_resources.is_empty() {
                let boundary_group_id = format!("{}_boundary", vpc_id);
                builder.add_group(&boundary_group_id, "Network Gateways");

                for node in &boundary.boundary_resources {
                    let icon = self.get_icon_for_resource(&node.resource_type);
                    let label = self.format_node_label(node);
                    builder.add_service(&node.id, &label, &boundary_group_id, &icon);
                }
            }

            // Add subnet tiers in proper order (public -> app -> db)
            let tier_order = [
                SubnetTier::Public,
                SubnetTier::PrivateApp,
                SubnetTier::PrivateDb,
                SubnetTier::Management,
            ];

            for tier in &tier_order {
                if let Some(tier_nodes) = boundary.tiers.get(tier) {
                    let tier_group_id = format!("{}_{}", vpc_id, tier.to_string());
                    let tier_label = tier.display_name();
                    builder.add_group(&tier_group_id, &tier_label);

                    for node in tier_nodes {
                        let icon = self.get_icon_for_resource(&node.resource_type);
                        let label = self.format_node_label(node);
                        builder.add_service(&node.id, &label, &tier_group_id, &icon);
                    }
                }
            }

            // Add any "Other" tier nodes
            for (tier, tier_nodes) in &boundary.tiers {
                if matches!(tier, SubnetTier::Other(_)) {
                    let tier_group_id = format!("{}_{}", vpc_id, tier.to_string());
                    let tier_label = tier.display_name();
                    builder.add_group(&tier_group_id, &tier_label);

                    for node in tier_nodes {
                        let icon = self.get_icon_for_resource(&node.resource_type);
                        let label = self.format_node_label(node);
                        builder.add_service(&node.id, &label, &tier_group_id, &icon);
                    }
                }
            }
        }

        // 4. Add External Interfaces (Users, Internet, etc.)
        if !zones.external_interfaces.is_empty() {
            builder.add_group("external", "External");
            for node in &zones.external_interfaces {
                let icon = self.get_icon_for_resource(&node.resource_type);
                let label = self.format_node_label(node);
                builder.add_service(&node.id, &label, "external", &icon);
            }
        }
    }

    /// Categorize a resource for trust zone placement
    fn categorize_resource(&self, resource_type: &str, node: &ResourceNode) -> ResourceCategory {
        match resource_type {
            "aws_iam_role" | "aws_iam_policy" | "aws_iam_user" | "aws_iam_group"
            | "aws_iam_instance_profile" => ResourceCategory::Identity,

            "aws_kms_key" | "aws_kms_alias" => ResourceCategory::KeyManagement,

            "aws_cloudtrail" | "aws_cloudwatch_log_group" | "aws_config_configuration_recorder"
            | "aws_guardduty_detector" | "aws_securityhub_account" | "aws_flow_log"
            | "aws_ssm_patch_baseline" => {
                ResourceCategory::AuditMonitoring
            }

            "aws_internet_gateway" | "aws_nat_gateway" | "aws_vpn_gateway"
            | "aws_security_group" | "aws_network_acl" => ResourceCategory::NetworkBoundary,

            "aws_instance" | "aws_ecs_service" | "aws_eks_cluster" | "aws_lambda_function"
            | "aws_autoscaling_group" => ResourceCategory::Compute,

            "aws_db_instance" | "aws_rds_cluster" | "aws_elasticache_cluster"
            | "aws_s3_bucket" | "aws_dynamodb_table" => ResourceCategory::DataStore,

            _ => {
                // Check if it's in a VPC/subnet
                if node.attributes.get("vpc_id").is_some() || node.attributes.get("subnet_id").is_some() {
                    ResourceCategory::Compute
                } else {
                    ResourceCategory::External
                }
            }
        }
    }

    /// Analyze edge metadata for enhanced annotations
    fn analyze_edge(&self, from: &str, to: &str, relationship: &str, nodes: &[ResourceNode]) -> EdgeMetadata {
        let from_node = nodes.iter().find(|n| n.id == from);
        let to_node = nodes.iter().find(|n| n.id == to);

        let mut metadata = EdgeMetadata {
            protocol: None,
            port: None,
            encrypted: false,
            kms_key: None,
            direction: "bidirectional".to_string(),
        };

        // Infer protocol and port from resource types and security group rules
        if let (Some(from_n), Some(to_n)) = (from_node, to_node) {
            // Check security group rules
            if from_n.resource_type == "aws_security_group" {
                if let Some(egress) = from_n.attributes.get("egress").and_then(|v| v.as_array()) {
                    for rule in egress {
                        if let Some(protocol) = rule.get("protocol").and_then(|v| v.as_str()) {
                            metadata.protocol = Some(protocol.to_string());
                            if let Some(port) = rule.get("from_port").and_then(|v| v.as_i64()) {
                                metadata.port = Some(port as u16);
                            }
                        }
                    }
                }
            }

            // Check for encryption
            if to_n.resource_type == "aws_db_instance" || to_n.resource_type == "aws_s3_bucket" {
                metadata.encrypted = to_n.attributes.get("storage_encrypted")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);

                if metadata.encrypted {
                    metadata.kms_key = to_n.attributes.get("kms_key_id")
                        .and_then(|v| v.as_str())
                        .map(|s| self.extract_key_id(s));
                }
            }
        }

        metadata.direction = relationship.to_string();
        metadata
    }

    fn get_vpc_id(&self, node: &ResourceNode) -> String {
        node.attributes.get("vpc_id")
            .and_then(|v| v.as_str())
            .unwrap_or("default-vpc")
            .to_string()
    }

    fn get_subnet_id(&self, node: &ResourceNode) -> String {
        node.attributes.get("subnet_id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string()
    }

    fn get_vpc_id_from_subnet(&self, subnet_id: &str, subnets: &[&ResourceNode]) -> String {
        subnets.iter()
            .find(|s| {
                s.attributes.get("id")
                    .and_then(|v| v.as_str())
                    .map(|id| id == subnet_id)
                    .unwrap_or(false)
            })
            .and_then(|s| s.attributes.get("vpc_id"))
            .and_then(|v| v.as_str())
            .unwrap_or("default-vpc")
            .to_string()
    }

    fn extract_key_id(&self, kms_arn: &str) -> String {
        kms_arn.split('/').last().unwrap_or(kms_arn).to_string()
    }

    /// Format a node label
    fn format_node_label(&self, node: &ResourceNode) -> String {
        // Try to get a friendly name from tags
        if let Some(name_tag) = node.attributes.get("tags")
            .and_then(|v| v.as_object())
            .and_then(|tags| tags.get("Name"))
            .and_then(|v| v.as_str()) {
            return name_tag.to_string();
        }

        // Fall back to resource name
        node.name.replace('_', " ")
    }

    /// Get an appropriate icon for a resource type (using MermaidChart AWS architecture icons)
    fn get_icon_for_resource(&self, resource_type: &str) -> String {
        match resource_type {
            // Compute
            "aws_instance" => "aws:arch-amazon-ec2",
            "aws_lambda_function" => "aws:arch-aws-lambda",
            "aws_ecs_service" | "aws_ecs_cluster" => "aws:arch-amazon-elastic-container-service",
            "aws_eks_cluster" | "aws_eks_node_group" => "aws:arch-amazon-elastic-kubernetes-service",
            "aws_autoscaling_group" => "aws:arch-aws-auto-scaling",

            // Storage
            "aws_s3_bucket" => "aws:arch-amazon-simple-storage-service",
            "aws_ebs_volume" => "aws:arch-amazon-elastic-block-store",
            "aws_efs_file_system" => "aws:arch-amazon-elastic-file-system",

            // Database
            "aws_db_instance" | "aws_rds_cluster" => "aws:arch-amazon-rds",
            "aws_dynamodb_table" => "aws:arch-amazon-dynamodb",
            "aws_elasticache_cluster" => "aws:arch-amazon-elasticache",
            "aws_docdb_cluster" => "aws:arch-amazon-documentdb",
            "aws_neptune_cluster" => "aws:arch-amazon-neptune",

            // Networking
            "aws_vpc" => "aws:arch-amazon-virtual-private-cloud",
            "aws_subnet" => "aws:private-subnet",
            "aws_internet_gateway" => "aws:res-amazon-vpc-internet-gateway",
            "aws_nat_gateway" => "aws:res-amazon-vpc-nat-gateway",
            "aws_vpn_gateway" => "aws:arch-aws-vpn",
            "aws_vpc_endpoint" => "aws:arch-aws-privatelink",
            "aws_dx_gateway" => "aws:arch-aws-direct-connect",

            // Security
            "aws_security_group" => "aws:arch-aws-network-firewall",
            "aws_network_acl" => "aws:arch-aws-network-firewall",
            "aws_kms_key" | "aws_kms_alias" => "aws:arch-aws-key-management-service",
            "aws_iam_role" | "aws_iam_policy" | "aws_iam_user" | "aws_iam_group" | "aws_iam_instance_profile" => "aws:arch-aws-identity-and-access-management",
            "aws_guardduty_detector" => "aws:arch-amazon-guardduty",
            "aws_securityhub_account" => "aws:arch-aws-security-hub",
            "aws_waf" | "aws_wafv2_web_acl" => "aws:arch-aws-waf",

            // Monitoring & Logging
            "aws_cloudwatch_log_group" => "aws:arch-amazon-cloudwatch",
            "aws_cloudtrail" => "aws:arch-aws-cloudtrail",
            "aws_config_configuration_recorder" => "aws:arch-aws-config",
            "aws_flow_log" => "aws:arch-amazon-cloudwatch",
            "aws_ssm_patch_baseline" => "aws:arch-aws-systems-manager",

            // Load Balancing
            "aws_lb" | "aws_alb" => "aws:arch-elastic-load-balancing",
            "aws_elb" => "aws:arch-elastic-load-balancing",

            // DNS & CDN
            "aws_route53_zone" => "aws:arch-amazon-route-53",
            "aws_cloudfront_distribution" => "aws:arch-amazon-cloudfront",

            // Default
            _ => "aws:arch-aws-cloud",
        }
        .to_string()
    }
}

/// Builder for Mermaid architecture diagrams
struct MermaidArchitectureBuilder {
    title: String,
    groups: Vec<(String, String)>, // (id, label)
    services: Vec<ServiceDef>,
    connections: Vec<ConnectionDef>,
}

struct ServiceDef {
    id: String,
    label: String,
    icon: String,
}

struct ConnectionDef {
    from: String,
    to: String,
    label: String,
    arrow_type: ArrowType,
}

#[derive(Debug, Clone)]
enum ArrowType {
    Bidirectional,  // L -- R (default)
    LeftToRight,    // L --> R
    RightToLeft,    // L <-- R
    Dotted,         // L -.-> R (for optional/async)
}

/// Trust zone hierarchy for compliance-oriented grouping
#[derive(Debug, Default)]
struct TrustZoneHierarchy {
    identity_plane: Vec<ResourceNode>,
    key_plane: Vec<ResourceNode>,
    audit_plane: Vec<ResourceNode>,
    network_boundaries: HashMap<String, NetworkBoundary>,
    external_interfaces: Vec<ResourceNode>,
    subnet_tiers: HashMap<String, SubnetTier>,
}

#[derive(Debug)]
struct NetworkBoundary {
    boundary_resources: Vec<ResourceNode>,
    tiers: HashMap<SubnetTier, Vec<ResourceNode>>,
}

impl NetworkBoundary {
    fn new(_vpc_id: &str) -> Self {
        Self {
            boundary_resources: Vec::new(),
            tiers: HashMap::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum SubnetTier {
    Public,
    PrivateApp,
    PrivateDb,
    Management,
    Other(String),
}

impl SubnetTier {
    fn display_name(&self) -> String {
        match self {
            SubnetTier::Public => "Public Subnet".to_string(),
            SubnetTier::PrivateApp => "Private Subnet (App)".to_string(),
            SubnetTier::PrivateDb => "Private Subnet (Data)".to_string(),
            SubnetTier::Management => "Private Subnet (Mgmt)".to_string(),
            SubnetTier::Other(name) => format!("{} Subnet", name),
        }
    }

    fn to_string(&self) -> String {
        match self {
            SubnetTier::Public => "public".to_string(),
            SubnetTier::PrivateApp => "private_app".to_string(),
            SubnetTier::PrivateDb => "private_db".to_string(),
            SubnetTier::Management => "mgmt".to_string(),
            SubnetTier::Other(name) => name.to_lowercase().replace(' ', "_"),
        }
    }
}

#[derive(Debug)]
enum ResourceCategory {
    Identity,
    KeyManagement,
    AuditMonitoring,
    NetworkBoundary,
    Compute,
    DataStore,
    External,
}

#[derive(Debug)]
struct EdgeMetadata {
    protocol: Option<String>,
    port: Option<u16>,
    encrypted: bool,
    kms_key: Option<String>,
    direction: String,
}

impl MermaidArchitectureBuilder {
    fn new(title: &str) -> Self {
        Self {
            title: title.to_string(),
            groups: Vec::new(),
            services: Vec::new(),
            connections: Vec::new(),
        }
    }

    fn add_group(&mut self, id: &str, label: &str) {
        self.groups.push((id.to_string(), label.to_string()));
    }

    fn add_service(&mut self, id: &str, label: &str, _group: &str, icon: &str) {
        // Sanitize IDs for Mermaid (replace dots with underscores)
        let sanitized_id = id.replace('.', "_").replace('-', "_");
        self.services.push(ServiceDef {
            id: sanitized_id,
            label: label.to_string(),
            icon: icon.to_string(),
        });
    }

    fn add_connection_with_arrow(&mut self, from: &str, to: &str, label: &str, arrow_type: ArrowType) {
        let sanitized_from = from.replace('.', "_").replace('-', "_");
        let sanitized_to = to.replace('.', "_").replace('-', "_");
        self.connections.push(ConnectionDef {
            from: sanitized_from,
            to: sanitized_to,
            label: label.to_string(),
            arrow_type,
        });
    }

    fn add_connection_with_metadata(&mut self, from: &str, to: &str, metadata: &EdgeMetadata) {
        // Do NOT add labels to connections - they cause parsing errors
        // Metadata is analyzed but not rendered in the diagram

        // Determine arrow type based on relationship
        let arrow_type = match metadata.direction.to_lowercase().as_str() {
            "depends_on" | "uses" | "reads" | "calls" => ArrowType::LeftToRight,
            "ingress" | "inbound" => ArrowType::RightToLeft,
            "egress" | "outbound" => ArrowType::LeftToRight,
            "async" | "eventual" => ArrowType::Dotted,
            _ => ArrowType::Bidirectional,
        };

        self.add_connection_with_arrow(from, to, "", arrow_type);
    }

    /// Sanitize label to remove special characters that cause parsing errors
    fn sanitize_label(&self, label: &str) -> String {
        label
            .replace(':', " ")
            .replace('/', " ")
            .replace('(', " ")
            .replace(')', " ")
            .replace('-', " ")
            .replace("  ", " ")
            .trim()
            .to_string()
    }

    fn build(&self) -> String {
        let mut diagram = String::new();

        // Header - Use flowchart for FedRAMP compliance visualization
        diagram.push_str("flowchart TB\n");
        diagram.push_str(&format!("    %% {}\n\n", self.title));

        // Build FedRAMP Authorization Boundary as main subgraph
        diagram.push_str("    subgraph boundary[\"<b>FedRAMP Authorization Boundary</b>\"]\n");
        diagram.push_str("        direction TB\n\n");

        // Groups as subgraphs with FedRAMP annotations
        for (id, label) in &self.groups {
            let sanitized_id = id.replace('.', "_").replace('-', "_");
            let sanitized_label = self.sanitize_label(label);

            // Add NIST control annotations based on group type
            let annotated_label = self.add_fedramp_annotations(&sanitized_id, &sanitized_label);

            diagram.push_str(&format!("        subgraph {}[\"<b>{}</b><br/> \"]\n", sanitized_id, annotated_label));
            diagram.push_str("            direction TB\n");
        }

        // Services as flowchart nodes with icons and encryption labels
        for service in &self.services {
            let sanitized_label = self.sanitize_label(&service.label);
            let encryption_label = self.get_encryption_label(&service.id);
            let icon_url = self.get_icon_url(&service.icon);

            diagram.push_str(&format!(
                "            {}[[\"<img src='{}' width='40'/><br/>{}{}\"]]\n",
                service.id, icon_url, sanitized_label, encryption_label
            ));
        }

        // Close all subgraphs
        for _ in &self.groups {
            diagram.push_str("        end\n");
        }
        diagram.push_str("    end\n\n");

        // External nodes (Internet, etc.)
        diagram.push_str("    internet[\"☁️ Internet - External Users\"]\n\n");

        // Connections with FedRAMP-compliant labels
        diagram.push_str("    %% Data Flow\n");
        for conn in &self.connections {
            let arrow_syntax = match conn.arrow_type {
                ArrowType::Bidirectional => "--",
                ArrowType::LeftToRight => "-->",
                ArrowType::RightToLeft => "<--",
                ArrowType::Dotted => "-.->",
            };

            let label = if !conn.label.is_empty() {
                format!("|\"{}\"| ", conn.label)
            } else {
                String::new()
            };

            diagram.push_str(&format!(
                "    {} {}{}{}\n",
                conn.from, arrow_syntax, label, conn.to
            ));
        }

        // Add styling for FedRAMP compliance zones
        diagram.push_str("\n    %% FedRAMP Compliance Styling\n");
        diagram.push_str("    style boundary fill:#e3f2fd,stroke:#1976d2,stroke-width:4px,stroke-dasharray: 10 5\n");

        // Style groups based on their security classification
        for (id, _) in &self.groups {
            let sanitized_id = id.replace('.', "_").replace('-', "_");
            if sanitized_id.contains("security") {
                diagram.push_str(&format!("    style {} fill:#fff3e0,stroke:#f57c00,stroke-width:2px\n", sanitized_id));
            } else if sanitized_id.contains("db") || sanitized_id.contains("data") {
                diagram.push_str(&format!("    style {} fill:#fce4ec,stroke:#c2185b,stroke-width:2px\n", sanitized_id));
            } else if sanitized_id.contains("public") {
                diagram.push_str(&format!("    style {} fill:#e8f5e9,stroke:#388e3c,stroke-width:2px\n", sanitized_id));
            }
        }

        diagram
    }

    /// Add FedRAMP NIST 800-53 control annotations to group labels
    fn add_fedramp_annotations(&self, group_id: &str, label: &str) -> String {
        if group_id.contains("security") {
            format!("{} - AC-6, AU-2", label)
        } else if group_id.contains("public") {
            format!("{} - SC-7 Boundary Protection", label)
        } else if group_id.contains("app") || group_id.contains("private") {
            format!("{} - Private (SC-7)", label)
        } else if group_id.contains("db") || group_id.contains("data") {
            format!("{} - Encrypted at Rest (SC-13)", label)
        } else {
            label.to_string()
        }
    }

    /// Get encryption label for resources
    fn get_encryption_label(&self, service_id: &str) -> String {
        if service_id.contains("ec2") || service_id.contains("web") || service_id.contains("app") || service_id.contains("instance") {
            "<br/>🔒 EBS-CMK".to_string()
        } else if service_id.contains("rds") || service_id.contains("db") {
            "<br/>🔒 KMS Encrypted".to_string()
        } else if service_id.contains("s3") {
            "<br/>🔒 KMS + Versioning".to_string()
        } else if service_id.contains("kms") {
            "<br/>SC-13".to_string()
        } else if service_id.contains("cloudtrail") {
            "<br/>AU-2".to_string()
        } else if service_id.contains("guardduty") {
            "<br/>IR-4".to_string()
        } else if service_id.contains("config") {
            "<br/>CM-6".to_string()
        } else if service_id.contains("flow_log") {
            "<br/>AU-12".to_string()
        } else {
            String::new()
        }
    }

    /// Convert AWS icon name to icon URL
    fn get_icon_url(&self, icon_name: &str) -> String {
        // Map AWS icon names to icepanel.io URLs
        match icon_name {
            "aws:arch-amazon-ec2" => "https://icon.icepanel.io/AWS/svg/Compute/EC2.svg",
            "aws:arch-amazon-rds" => "https://icon.icepanel.io/AWS/svg/Database/RDS.svg",
            "aws:arch-amazon-simple-storage-service" => "https://icon.icepanel.io/AWS/svg/Storage/Simple-Storage-Service.svg",
            "aws:arch-amazon-virtual-private-cloud" => "https://icon.icepanel.io/AWS/svg/Networking-Content-Delivery/Virtual-Private-Cloud.svg",
            "aws:res-amazon-vpc-internet-gateway" => "https://cdn.prod.website-files.com/5f05d5858fab461d0d08eaeb/635a1c060b1a32823c9159d0_internet_gateway_light.svg",
            "aws:res-amazon-vpc-nat-gateway" => "https://cdn.prod.website-files.com/5f05d5858fab461d0d08eaeb/6358cec281674a47f95c499b_nat_gateway_light.svg",
            "aws:arch-aws-network-firewall" => "https://icon.icepanel.io/AWS/svg/Security-Identity-Compliance/Network-Firewall.svg",
            "aws:arch-aws-key-management-service" => "https://icon.icepanel.io/AWS/svg/Security-Identity-Compliance/Key-Management-Service.svg",
            "aws:arch-aws-cloudtrail" => "https://icon.icepanel.io/AWS/svg/Management-Governance/CloudTrail.svg",
            "aws:arch-amazon-guardduty" => "https://icon.icepanel.io/AWS/svg/Security-Identity-Compliance/GuardDuty.svg",
            "aws:arch-aws-config" => "https://icon.icepanel.io/AWS/svg/Management-Governance/Config.svg",
            "aws:arch-amazon-cloudwatch" => "https://icon.icepanel.io/AWS/svg/Management-Governance/CloudWatch.svg",
            "aws:arch-aws-identity-and-access-management" => "https://icon.icepanel.io/AWS/svg/Security-Identity-Compliance/Identity-and-Access-Management.svg",
            "aws:arch-elastic-load-balancing" => "https://icon.icepanel.io/AWS/svg/Networking-Content-Delivery/Elastic-Load-Balancing.svg",
            "aws:arch-aws-systems-manager" => "https://icon.icepanel.io/AWS/svg/Management-Governance/Systems-Manager.svg",
            _ => "https://icon.icepanel.io/AWS/svg/General/AWS-Cloud.svg",
        }.to_string()
    }
}

/// Generated Mermaid diagram with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MermaidDiagram {
    pub content: String,
    pub node_count: usize,
    pub edge_count: usize,
    pub metadata: DiagramMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiagramMetadata {
    pub title: String,
    pub generated_at: String,
    pub categories: HashMap<String, usize>,
    pub zones: HashMap<String, usize>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mermaid_builder() {
        let mut builder = MermaidArchitectureBuilder::new("Test Architecture");
        builder.add_group("public", "Public Zone");
        builder.add_service("web_server", "Web Server", "public", "server");
        builder.add_connection("web_server", "app_server", "https");

        let diagram = builder.build();
        assert!(diagram.contains("architecture-beta"));
        assert!(diagram.contains("title Test Architecture"));
    }
}
