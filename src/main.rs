use axum::{
    routing::post,
    Router,
};
use hayashi::{
    api::handlers::{diagram_handler},
};
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tower::ServiceBuilder;
use tower_http::cors::CorsLayer;
use tracing::info;
use tracing_subscriber;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let app = Router::new()
        .route("/v1/diagram", post(diagram_handler))
        .layer(ServiceBuilder::new().layer(CorsLayer::permissive()));

    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    info!("Nabla Evidence API listening on {}", addr);

    let listener = TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}