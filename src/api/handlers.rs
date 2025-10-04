use crate::{
    api::models::{ApiError, DiagramRequest, DiagramResponse, DiagramMetadata},
    diagram::statefile::StatefileParser,
    diagram::graph::ResourceGraph,
    diagram::mermaid::MermaidGenerator,
};
use axum::{
    http::StatusCode,
    response::Json,
};
use tracing::{error, info};

pub async fn diagram_handler(
    Json(request): Json<DiagramRequest>,
) -> Result<Json<DiagramResponse>, (StatusCode, Json<ApiError>)> {
    // Extract customer key from headers

    info!("Processing diagram request: {}", request.name);

    // Parse the statefile
    let statefile_data = StatefileParser::parse_statefile(&request.statefile_path)
        .await
        .map_err(|e| {
            error!("Failed to parse statefile: {}", e);
            (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(ApiError::unprocessable_entity(&format!(
                    "Failed to parse statefile: {}",
                    e
                ))),
            )
        })?;

    // Build resource graph
    let graph = ResourceGraph::from_statefile(&statefile_data).map_err(|e| {
        error!("Failed to build resource graph: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiError::internal_server_error(&format!(
                "Failed to build resource graph: {}",
                e
            ))),
        )
    })?;

    info!(
        "Built resource graph with {} nodes and {} edges",
        graph.nodes.len(),
        graph.edges.len()
    );

    // Initialize Mermaid generator with Workers AI
    let mermaid_generator = match (request.model, request.api_key) {
        (Some(model), Some(api_key)) => MermaidGenerator::with_model_and_key(model, api_key),
        (Some(model), None) => MermaidGenerator::with_model(model),
        (None, Some(api_key)) => MermaidGenerator::with_model_and_key("@cf/openai/gpt-oss-120b".to_string(), api_key),
        (None, None) => MermaidGenerator::new(),
    }
    .map_err(|e| {
        error!("Failed to create Mermaid generator: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiError::internal_server_error(&format!(
                "Failed to initialize Mermaid generator: {}",
                e
            ))),
        )
    })?;

    // Generate Mermaid diagram
    let diagram = mermaid_generator
        .generate_architecture_diagram(&graph, &request.name)
        .await
        .map_err(|e| {
            error!("Failed to generate diagram: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiError::internal_server_error(&format!(
                    "Failed to generate diagram: {}",
                    e
                ))),
            )
        })?;

    info!("Successfully generated Mermaid diagram");

    Ok(Json(DiagramResponse {
        mermaid_content: diagram.content,
        metadata: DiagramMetadata {
            generated_at: diagram.metadata.generated_at,
            node_count: diagram.node_count,
            edge_count: diagram.edge_count,
            title: diagram.metadata.title,
        },
    }))
}