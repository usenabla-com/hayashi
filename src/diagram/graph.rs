//! Resource graph extraction from Terraform statefiles
//! Builds a directed graph of infrastructure resources with relationships

use crate::diagram::statefile::{StatefileData, TerraformResource};
use anyhow::Result;
use petgraph::graph::{DiGraph, NodeIndex};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

/// A node in the resource graph
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceNode {
    pub id: String,
    pub resource_type: String,
    pub name: String,
    pub provider: String,
    pub attributes: HashMap<String, Value>,
    /// Categorization for diagram grouping (e.g., "compute", "network", "storage")
    pub category: String,
    /// Security zone (e.g., "public", "private", "database")
    pub zone: Option<String>,
}

/// An edge in the resource graph
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceEdge {
    pub from: String,
    pub to: String,
    pub relationship: String,
}

/// Resource graph structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceGraph {
    pub nodes: Vec<ResourceNode>,
    pub edges: Vec<ResourceEdge>,
}

impl ResourceGraph {
    /// Build a resource graph from parsed statefile data
    pub fn from_statefile(statefile: &StatefileData) -> Result<Self> {
        let mut nodes = Vec::new();
        let mut edges = Vec::new();
        let mut resource_map: HashMap<String, ResourceNode> = HashMap::new();

        // First pass: create nodes
        for resource in &statefile.resources {
            let node = Self::resource_to_node(resource);
            resource_map.insert(node.id.clone(), node.clone());
            nodes.push(node);
        }

        // Second pass: extract relationships
        for resource in &statefile.resources {
            let from_id = Self::resource_id(resource);

            // Extract VPC relationships
            if let Some(vpc_id) = resource.attributes.get("vpc_id").and_then(|v| v.as_str()) {
                if let Some(to_id) = Self::find_resource_by_attribute(&resource_map, "id", vpc_id) {
                    edges.push(ResourceEdge {
                        from: from_id.clone(),
                        to: to_id,
                        relationship: "in_vpc".to_string(),
                    });
                }
            }

            // Extract subnet relationships
            if let Some(subnet_id) = resource.attributes.get("subnet_id").and_then(|v| v.as_str()) {
                if let Some(to_id) = Self::find_resource_by_attribute(&resource_map, "id", subnet_id) {
                    edges.push(ResourceEdge {
                        from: from_id.clone(),
                        to: to_id,
                        relationship: "in_subnet".to_string(),
                    });
                }
            }

            // Extract security group relationships
            if let Some(sg_ids) = resource.attributes.get("vpc_security_group_ids").and_then(|v| v.as_array()) {
                for sg_id in sg_ids {
                    if let Some(sg_id_str) = sg_id.as_str() {
                        if let Some(to_id) = Self::find_resource_by_attribute(&resource_map, "id", sg_id_str) {
                            edges.push(ResourceEdge {
                                from: from_id.clone(),
                                to: to_id,
                                relationship: "uses_security_group".to_string(),
                            });
                        }
                    }
                }
            }

            // Extract NAT gateway relationships
            if resource.resource_type == "aws_nat_gateway" {
                if let Some(subnet_id) = resource.attributes.get("subnet_id").and_then(|v| v.as_str()) {
                    if let Some(to_id) = Self::find_resource_by_attribute(&resource_map, "id", subnet_id) {
                        edges.push(ResourceEdge {
                            from: from_id.clone(),
                            to: to_id,
                            relationship: "nat_in_subnet".to_string(),
                        });
                    }
                }
            }

            // Extract internet gateway relationships
            if resource.resource_type == "aws_internet_gateway" {
                if let Some(vpc_id) = resource.attributes.get("vpc_id").and_then(|v| v.as_str()) {
                    if let Some(to_id) = Self::find_resource_by_attribute(&resource_map, "id", vpc_id) {
                        edges.push(ResourceEdge {
                            from: from_id.clone(),
                            to: to_id,
                            relationship: "gateway_for_vpc".to_string(),
                        });
                    }
                }
            }

            // Extract KMS key relationships
            if let Some(kms_key_id) = resource.attributes.get("kms_key_id").and_then(|v| v.as_str()) {
                if let Some(to_id) = Self::find_resource_by_id_or_arn(&resource_map, kms_key_id) {
                    edges.push(ResourceEdge {
                        from: from_id.clone(),
                        to: to_id,
                        relationship: "encrypted_with".to_string(),
                    });
                }
            }
        }

        Ok(ResourceGraph { nodes, edges })
    }

    /// Convert a Terraform resource to a graph node
    fn resource_to_node(resource: &TerraformResource) -> ResourceNode {
        let id = Self::resource_id(resource);
        let category = Self::categorize_resource(&resource.resource_type);
        let zone = Self::determine_zone(resource);

        ResourceNode {
            id,
            resource_type: resource.resource_type.clone(),
            name: resource.name.clone(),
            provider: resource.provider.clone(),
            attributes: resource.attributes.clone(),
            category,
            zone,
        }
    }

    /// Generate a unique ID for a resource
    fn resource_id(resource: &TerraformResource) -> String {
        format!("{}.{}", resource.resource_type, resource.name)
    }

    /// Categorize a resource type for diagram grouping
    fn categorize_resource(resource_type: &str) -> String {
        match resource_type {
            // Compute
            "aws_instance" | "aws_launch_template" | "aws_autoscaling_group" => "compute".to_string(),

            // Network
            "aws_vpc" | "aws_subnet" | "aws_internet_gateway" | "aws_nat_gateway"
            | "aws_route_table" | "aws_network_acl" => "network".to_string(),

            // Security
            "aws_security_group" | "aws_iam_role" | "aws_iam_policy" | "aws_kms_key" => "security".to_string(),

            // Storage
            "aws_s3_bucket" | "aws_ebs_volume" => "storage".to_string(),

            // Database
            "aws_db_instance" | "aws_rds_cluster" | "aws_dynamodb_table" => "database".to_string(),

            // Monitoring
            "aws_cloudwatch_log_group" | "aws_cloudtrail" => "monitoring".to_string(),

            // Load balancing
            "aws_lb" | "aws_alb" | "aws_elb" => "load_balancer".to_string(),

            _ => "other".to_string(),
        }
    }

    /// Determine the security zone of a resource
    fn determine_zone(resource: &TerraformResource) -> Option<String> {
        // Check tags for explicit zone/tier classification
        if let Some(tags) = resource.attributes.get("tags").and_then(|v| v.as_object()) {
            if let Some(zone_type) = tags.get("Type").and_then(|v| v.as_str()) {
                return Some(zone_type.to_lowercase());
            }
        }

        // Infer from resource type
        match resource.resource_type.as_str() {
            "aws_internet_gateway" | "aws_nat_gateway" => Some("public".to_string()),
            "aws_db_instance" | "aws_rds_cluster" => Some("database".to_string()),
            _ => {
                // Check if subnet is public (map_public_ip_on_launch)
                if let Some(map_public) = resource.attributes.get("map_public_ip_on_launch").and_then(|v| v.as_bool()) {
                    if map_public {
                        return Some("public".to_string());
                    } else {
                        return Some("private".to_string());
                    }
                }
                None
            }
        }
    }

    /// Find a resource by matching an attribute value
    fn find_resource_by_attribute(
        resource_map: &HashMap<String, ResourceNode>,
        attribute: &str,
        value: &str,
    ) -> Option<String> {
        resource_map.iter()
            .find(|(_, node)| {
                node.attributes.get(attribute)
                    .and_then(|v| v.as_str())
                    .map(|s| s == value)
                    .unwrap_or(false)
            })
            .map(|(id, _)| id.clone())
    }

    /// Find a resource by ID or ARN
    fn find_resource_by_id_or_arn(
        resource_map: &HashMap<String, ResourceNode>,
        id_or_arn: &str,
    ) -> Option<String> {
        // Try exact ID match first
        if let Some(id) = Self::find_resource_by_attribute(resource_map, "id", id_or_arn) {
            return Some(id);
        }

        // Try ARN match
        if let Some(id) = Self::find_resource_by_attribute(resource_map, "arn", id_or_arn) {
            return Some(id);
        }

        // Extract ID from ARN if it's an ARN
        if id_or_arn.starts_with("arn:") {
            if let Some(resource_id) = id_or_arn.split('/').last() {
                return Self::find_resource_by_attribute(resource_map, "id", resource_id);
            }
        }

        None
    }

    /// Convert to a petgraph DiGraph for advanced graph operations
    pub fn to_digraph(&self) -> DiGraph<ResourceNode, String> {
        let mut graph = DiGraph::new();
        let mut node_indices: HashMap<String, NodeIndex> = HashMap::new();

        // Add nodes
        for node in &self.nodes {
            let idx = graph.add_node(node.clone());
            node_indices.insert(node.id.clone(), idx);
        }

        // Add edges
        for edge in &self.edges {
            if let (Some(&from_idx), Some(&to_idx)) = (
                node_indices.get(&edge.from),
                node_indices.get(&edge.to),
            ) {
                graph.add_edge(from_idx, to_idx, edge.relationship.clone());
            }
        }

        graph
    }

    /// Get a summary of the graph
    pub fn summary(&self) -> GraphSummary {
        let mut categories: HashMap<String, usize> = HashMap::new();
        let mut zones: HashMap<String, usize> = HashMap::new();

        for node in &self.nodes {
            *categories.entry(node.category.clone()).or_insert(0) += 1;
            if let Some(zone) = &node.zone {
                *zones.entry(zone.clone()).or_insert(0) += 1;
            }
        }

        GraphSummary {
            node_count: self.nodes.len(),
            edge_count: self.edges.len(),
            categories,
            zones,
        }
    }
}

/// Summary statistics for a resource graph
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphSummary {
    pub node_count: usize,
    pub edge_count: usize,
    pub categories: HashMap<String, usize>,
    pub zones: HashMap<String, usize>,
}
