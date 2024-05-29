use std::{
    net::{TcpListener, TcpStream},
    thread,
};

use anyhow::{Context, Result};
use decoding::{decode_packet, u8_to_MessageType};
use handshake::{ident_exchange, key_exchange};
use log::{debug, error, trace, warn};
use types::MessageType;

mod decoding;
mod encoding;
mod handshake;
mod types;
mod utils;

const PORT: usize = 6969;

fn main() -> Result<()> {
    env_logger::builder().format_target(false).init();
    if let Err(err) = connect() {
        error!("{:?}", err);
    }

    Ok(())
}

fn connect() -> Result<()> {
    let listener = TcpListener::bind(format!("127.0.0.1:{}", PORT))?;

    for client in listener.incoming() {
        let client = client.context("Client is invalid")?;
        let client_addr = client.peer_addr().unwrap();

        let handle = thread::spawn::<_, Result<()>>(|| {
            handle_client(client)?;
            Ok(())
        });

        match handle.join() {
            Ok(val) => match val {
                Ok(()) => debug!("Thread for address {} finished successfully", client_addr),
                Err(err) => error!(
                    "Thread for address {} finished with error: {:?}",
                    client_addr, err
                ),
            },
            Err(err) => error!("Thread for address {} panicked: {:?}", client_addr, err),
        }
    }

    Ok(())
}

fn handle_client(mut stream: TcpStream) -> Result<()> {
    debug!(
        "Spawned new thread for client on address {}",
        stream.peer_addr().unwrap()
    );

    ident_exchange(&mut stream).context("Failed during ident exchange")?;

    // First request after ident exchange is always key exchange
    let _client_algorithms = key_exchange(&mut stream).context("Failed during key exchange")?;

    Ok(())
}
