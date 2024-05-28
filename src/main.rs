use std::net::{TcpListener, TcpStream};

use anyhow::{Context, Result};
use handshake::{ident_exchange, key_exchange};
use log::info;
use utils::log_error;

mod decoding;
mod encoding;
mod handshake;
mod types;
mod utils;

const PORT: usize = 6969;

fn main() -> Result<()> {
    env_logger::builder().format_target(false).init();
    connect().unwrap_or_else(log_error);

    Ok(())
}

fn connect() -> Result<()> {
    let addr = format!("127.0.0.1:{}", PORT);
    let listener = TcpListener::bind(addr.clone())?;

    for client in listener.incoming() {
        let client = client.with_context(|| "Client is invalid")?;
        let addr = client.peer_addr().unwrap();
        handle_client(client).with_context(|| format!("Error while handling {}", addr))?;
    }

    Ok(())
}

fn handle_client(mut stream: TcpStream) -> Result<()> {
    info!(
        "Spawned new thread for client on address '{}'",
        stream.peer_addr()?
    );

    ident_exchange(&mut stream).with_context(|| "Failed during ident exchange")?;
    let _client_algorithms =
        key_exchange(&mut stream).with_context(|| "Failed during key exchange")?;

    Ok(())
}
