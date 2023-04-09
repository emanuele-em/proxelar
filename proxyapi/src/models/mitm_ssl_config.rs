use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Clone, Deserialize, Serialize)]
pub struct MitmSslConfig {
    pub cert: PathBuf,
    pub key: PathBuf,
}
