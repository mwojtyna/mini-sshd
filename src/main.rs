use std::{
    io::{BufRead, BufReader, Read, Write},
    net::{TcpListener, TcpStream},
};

use anyhow::{Context, Result};
use log::{debug, error, info, LevelFilter};

const PORT: usize = 6969;
const VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() -> Result<()> {
    let mut log_builder = env_logger::builder();
    if cfg!(debug_assertions) {
        log_builder.filter_level(LevelFilter::Debug);
    }
    log_builder.format_target(false);
    log_builder.init();

    connect().unwrap_or_else(log_error);

    Ok(())
}

fn connect() -> Result<()> {
    let addr = format!("127.0.0.1:{}", PORT);
    let listener = TcpListener::bind(addr.clone())
        .with_context(|| format!("Failed to connect to {}", addr))?;

    for client in listener.incoming() {
        // TODO: Don't crash program when error occurred
        handle_client(client?)?
    }

    Ok(())
}

fn handle_client(mut client: TcpStream) -> Result<()> {
    info!("Connected to client on address '{}'", client.peer_addr()?);

    // Identification exchange (RFC 4253 § 4.2)
    client.write_all(format!("SSH-2.0-minisshd_{}\r\n", VERSION).as_bytes())?;

    let mut reader = BufReader::new(client);
    let mut client_ident = String::new();
    reader.read_line(&mut client_ident)?;
    debug!("client = {:?}", client_ident);

    Ok(())
}

fn log_error(err: anyhow::Error) {
    error!("{}", err);
}
