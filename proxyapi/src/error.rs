use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error{
    #[error("network error")]
    Network(#[from] hyper::Error),
    #[error("unable to decode body")]
    Decode,
    #[error("unknown error")]
    Unknown,
}