pub mod check;
pub mod ci;
pub mod conflicts;
pub mod init;
pub mod list;
pub mod status;

use crate::client::ClientError;

#[derive(Debug, thiserror::Error)]
pub enum CommandError {
    #[error("client error: {0}")]
    Client(#[from] ClientError),

    #[error("daemon error: {0}")]
    DaemonError(String),

    #[error("invalid input: {0}")]
    InvalidInput(String),

    #[error("analysis error: {0}")]
    AnalysisError(String),

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("output error: {0}")]
    Output(#[from] std::io::Error),
}
