pub mod db;
pub mod lifecycle;
pub mod socket;
pub mod state;
pub mod watcher;

pub async fn run() {
    tracing::info!("grove daemon starting");
}
