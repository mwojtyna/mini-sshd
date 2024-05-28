use std::net::{TcpListener, TcpStream};

use anyhow::Result;
use handshake::{ident_exchange, key_exchange};
use log::{error, info, LevelFilter};
use utils::log_error;

mod handshake;
mod parsers;
mod types;
mod utils;

const PORT: usize = 6969;

fn main() -> Result<()> {
    let mut log_builder = env_logger::builder();
    if cfg!(debug_assertions) {
        log_builder.filter_level(LevelFilter::Debug);
    } else {
        log_builder.filter_level(LevelFilter::Info);
    }
    log_builder.format_target(false);
    log_builder.init();

    connect().unwrap_or_else(log_error);

    Ok(())
}

fn connect() -> Result<()> {
    let addr = format!("127.0.0.1:{}", PORT);
    let listener = TcpListener::bind(addr.clone())?;

    for client in listener.incoming() {
        match client {
            Ok(client) => {
                let addr = client.peer_addr().unwrap();
                if let Err(err) = handle_client(client) {
                    error!("Error while handling {}: {}", addr, err);
                }
            }
            Err(err) => {
                error!("Client is invalid: {}", err);
            }
        };
    }

    Ok(())
}

fn handle_client(mut stream: TcpStream) -> Result<()> {
    info!(
        "Spawned new thread for client on address '{}'",
        stream.peer_addr()?
    );

    ident_exchange(&mut stream)?;
    let client_algorithms = key_exchange(&mut stream)?;

    Ok(())
}
