use anyhow::{anyhow, Result};
use reqwest;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::path::Path;
use tokio::fs;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TerraformResource {
    pub resource_type: String,
    pub name: String,
    pub provider: String,
    pub attributes: HashMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatefileData {
    pub version: i32,
    pub resources: Vec<TerraformResource>,
}

pub struct StatefileParser;

impl StatefileParser {
    pub async fn parse_statefile(path: &str) -> Result<StatefileData> {
        let content = if path.starts_with("http://") || path.starts_with("https://") {
            // Remote statefile
            let response = reqwest::get(path).await?;
            response.text().await?
        } else {
            // Local statefile
            if !Path::new(path).exists() {
                return Err(anyhow!("Statefile not found at path: {}", path));
            }
            fs::read_to_string(path).await?
        };

        let statefile: Value = serde_json::from_str(&content)?;

        let version = statefile["version"]
            .as_i64()
            .unwrap_or(4) as i32;

        let mut resources = Vec::new();

        if let Some(resources_array) = statefile["resources"].as_array() {
            for resource in resources_array {
                if let (Some(resource_type), Some(name), Some(provider)) = (
                    resource["type"].as_str(),
                    resource["name"].as_str(),
                    resource["provider"].as_str(),
                ) {
                    let attributes = resource["instances"]
                        .as_array()
                        .and_then(|instances| instances.first())
                        .and_then(|instance| instance["attributes"].as_object())
                        .map(|attrs| {
                            attrs.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
                        })
                        .unwrap_or_default();

                    resources.push(TerraformResource {
                        resource_type: resource_type.to_string(),
                        name: name.to_string(),
                        provider: provider.to_string(),
                        attributes,
                    });
                }
            }
        }

        Ok(StatefileData { version, resources })
    }
}