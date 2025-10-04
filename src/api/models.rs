use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct DiagramRequest {
    pub name: String,
    pub statefile_path: String,
    pub model: Option<String>,
    pub api_key: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct DiagramResponse {
    pub mermaid_content: String,
    pub metadata: DiagramMetadata,
}

#[derive(Debug, Serialize)]
pub struct DiagramMetadata {
    pub generated_at: String,
    pub node_count: usize,
    pub edge_count: usize,
    pub title: String,
}

#[derive(Debug, Serialize)]
pub struct ApiError {
    pub error: String,
    pub message: String,
    pub code: Option<String>,
    #[serde(rename = "requestId")]
    pub request_id: Option<String>,
}

impl ApiError {
    pub fn bad_request(message: &str) -> Self {
        Self {
            error: "Bad Request".to_string(),
            message: message.to_string(),
            code: Some("400".to_string()),
            request_id: None,
        }
    }

    pub fn unauthorized(message: &str) -> Self {
        Self {
            error: "Unauthorized".to_string(),
            message: message.to_string(),
            code: Some("401".to_string()),
            request_id: None,
        }
    }

    pub fn unprocessable_entity(message: &str) -> Self {
        Self {
            error: "Unprocessable Entity".to_string(),
            message: message.to_string(),
            code: Some("422".to_string()),
            request_id: None,
        }
    }

    pub fn internal_server_error(message: &str) -> Self {
        Self {
            error: "Internal Server Error".to_string(),
            message: message.to_string(),
            code: Some("500".to_string()),
            request_id: None,
        }
    }
}