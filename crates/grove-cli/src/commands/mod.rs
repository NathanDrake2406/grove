pub mod conflicts;
pub mod list;
pub mod status;

use crate::client::ClientError;

#[derive(Debug, thiserror::Error)]
pub enum CommandError {
    #[error("client error: {0}")]
    Client(#[from] ClientError),

    #[error("daemon error: {0}")]
    DaemonError(String),

    #[error("output error: {0}")]
    Output(#[from] std::io::Error),
}
