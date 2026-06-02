// **********************************
// IMPORTS
// **********************************
use axum::{routing::put, Json, Router};
use std::process::Command;

// **********************************
// MAIN DAEMON ENTRY POINT
// **********************************
#[tokio::main]
async fn main() {
    let app = Router::new().route("/configs", put(apply_config));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:9090").await.unwrap();
    
    println!("KarinProxy Daemon is running on port 9090...");
    axum::serve(listener, app).await.unwrap();
}

// **********************************
// CONFIGURATION HANDLER
// **********************************
async fn apply_config(Json(config): Json<serde_json::Value>) -> &'static str {
    let config_path = "/etc/karin-proxy/config.json";
    let json_str = serde_json::to_string_pretty(&config).unwrap_or_default();
    
    let _ = std::fs::write(config_path, json_str);

    Command::new("sudo")
        .args(["systemctl", "restart", "karin-proxy-daemon"])
        .status()
        .ok();
    
    "OK"
}