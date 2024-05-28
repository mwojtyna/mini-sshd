use std::fmt::{Debug, Display};

use anyhow::anyhow;
use log::error;

pub fn packet_too_short(var_name: &str) -> Result<(), anyhow::Error> {
    Err(anyhow!(
        "Packet too short - '{}' could not be read",
        var_name
    ))
}

pub fn log_error(err: impl Debug) {
    error!("{:?}", err);
}
