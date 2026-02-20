pub mod db;
pub mod state;
pub mod watcher;

pub async fn run() {
    tracing::info!("grove daemon starting");
}
