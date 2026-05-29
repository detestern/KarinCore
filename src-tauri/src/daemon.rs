// *************************
// IMPORTS
// *************************
use axum::{routing::put, Json, Router};
use std::process::Command;

// *************************
// MAIN DAEMON ENTRY POINT
// *************************
#[tokio::main]
async fn main() {
    // Initialize the router
    let app = Router::new()
        .route("/configs", put(apply_config));

    // Bind the listener to localhost
    let listener = tokio::net::TcpListener::bind("127.0.0.1:9090").await.unwrap();
    println!("KarinProxy Daemon is running on port 9090...");
    
    // Start the HTTP server
    axum::serve(listener, app).await.unwrap();
}

// *************************
// CONFIGURATION HANDLER
// *************************
/// Handles incoming JSON configuration updates via PUT requests.
/// Writes the new config to the system directory and delegates process management to systemd.
async fn apply_config(Json(config): Json<serde_json::Value>) -> &'static str {
    let config_path = "/etc/karin-proxy/config.json";
    
    // 1. Write the new configuration to disk
    let json_str = serde_json::to_string_pretty(&config).unwrap_or_default();
    let _ = std::fs::write(config_path, json_str);

    // 2. Delegate restart to systemd
    // Systemd safely handles the actual Xray process lifecycle, no manual child killing needed
    Command::new("sudo")
        .args(["systemctl", "restart", "karin-proxy-daemon"])
        .status()
        .ok();
    
    "OK"
}