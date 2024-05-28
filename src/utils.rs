use std::fmt::Debug;

use anyhow::{anyhow, Result};
use log::error;

pub fn packet_too_short<T>(var_name: &str) -> Result<T> {
    Err(anyhow!(
        "Packet too short - '{}' could not be read",
        var_name
    ))
}

pub fn log_error(err: impl Debug) {
    error!("{:?}", err);
}
