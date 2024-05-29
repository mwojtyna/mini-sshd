use std::{
    io::{BufRead, BufReader, Write},
    net::{TcpListener, TcpStream},
    thread,
};

use anyhow::{Context, Result};
use const_format::formatcp;
use decoding::{decode_packet, u8_to_MessageType};
use encoding::encode_packet;
use handlers::key_exchange::key_exchange;
use log::{debug, error, trace};
use types::{DisconnectReason, MessageType};

mod decoding;
mod encoding;
mod handlers;
mod types;

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

    loop {
        let disconnect = handle_packet(&mut stream).context("Failed handling packet")?;
        if let Some(reason) = disconnect {
            debug!("Sending disconnect packet, reason = {:?}", reason);

            let payload = &[
                vec![MessageType::SSH_MSG_DISCONNECT as u8],
                vec![reason as u8],
                b"".to_vec(),
                b"en".to_vec(),
            ]
            .concat();

            let packet = encode_packet(payload)?;
            stream.write_all(&packet)?;

            break;
        }
    }

    Ok(())
}

const IDENT_STRING: &str = formatcp!("SSH-2.0-minisshd_{}\r\n", VERSION);
const VERSION: &str = env!("CARGO_PKG_VERSION");

// RFC 4253 § 4.2
pub fn ident_exchange(stream: &mut TcpStream) -> Result<()> {
    debug!("--- BEGIN IDENTIFICATION EXCHANGE ---");
    stream.write_all(IDENT_STRING.as_bytes())?;

    let mut reader = BufReader::new(stream);
    let mut client_ident = String::new();
    reader
        .read_line(&mut client_ident)
        .context("Failed reading client_ident")?;
    client_ident = client_ident.lines().next().unwrap().to_string();
    debug!("client = {:?}", client_ident);

    debug!("--- END IDENTIFICATION EXCHANGE ---");
    Ok(())
}

fn handle_packet(stream: &mut TcpStream) -> Result<Option<DisconnectReason>> {
    let payload = decode_packet(stream)?;
    let msg_type = u8_to_MessageType(payload[0])?;
    trace!("Received message type: {:?}", msg_type);

    match msg_type {
        MessageType::SSH_MSG_DISCONNECT => {
            return Ok(Some(DisconnectReason::SSH_DISCONNECT_BY_APPLICATION));
        }
        MessageType::SSH_MSG_KEXINIT => {
            key_exchange(stream)?;
        }
        _ => {
            error!(
                "Unhandled message type, exiting.\ntype: {:?}\npayload: {:?}",
                msg_type,
                String::from_utf8_lossy(&payload)
            );
            return Ok(Some(DisconnectReason::SSH_DISCONNECT_PROTOCOL_ERROR));
        }
    }

    Ok(None)
}
