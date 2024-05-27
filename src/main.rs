use std::{
    io::{BufRead, BufReader, Write},
    net::{TcpListener, TcpStream},
};

use anyhow::{anyhow, Context, Result};
use log::{debug, error, info, LevelFilter};
use num_traits::FromPrimitive;
use parsers::u8_to_bool;

use crate::{
    parsers::{parse_name_list, parse_packet},
    types::MessageType,
};

mod parsers;
mod types;

const PORT: usize = 6969;
const VERSION: &str = env!("CARGO_PKG_VERSION");

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
        }
    }

    Ok(())
}

fn handle_client(mut stream: TcpStream) -> Result<()> {
    info!("Connected to client on address '{}'", stream.peer_addr()?);

    // Identification exchange (RFC 4253 § 4.2)
    debug!("--- BEGIN IDENTIFICATION EXCHANGE ---");
    stream.write_all(format!("SSH-2.0-minisshd_{}\r\n", VERSION).as_bytes())?;

    let mut reader = BufReader::new(&stream);
    let mut client_ident = String::new();
    reader
        .read_line(&mut client_ident)
        .with_context(|| "Failed reading client_ident")?;
    client_ident = client_ident.lines().next().unwrap().to_string();
    debug!("client = {:?}", client_ident);

    debug!("--- END IDENTIFICATION EXCHANGE ---");

    // Key exchange (RFC 4253 § 7)
    debug!("--- BEGIN KEY EXCHANGE ---");
    let payload = parse_packet(&stream)?;
    let mut reader = payload.iter();

    if let Some(msg_type) = reader.next() {
        if let Some(msg_type_enum) = MessageType::from_u8(*msg_type) {
            debug!("msg_type = {:?}", msg_type_enum);
            if msg_type_enum != MessageType::SSH_MSG_KEXINIT {
                return Err(anyhow!("Expected SSH_MSG_KEXINIT, got {:?}", msg_type_enum));
            }
        } else {
            return Err(anyhow!("Failed casting msg_type"));
        }
    } else {
        return packet_too_short("msg_type");
    }

    let cookie = reader.by_ref().take(16).copied().collect::<Vec<u8>>();
    debug!("cookie = {:?}", cookie);

    let kex_algorithms = parse_name_list(&mut reader)?;
    debug!("kex_algorithms = {:?}", kex_algorithms);

    let server_host_key_algorithms = parse_name_list(&mut reader)?;
    debug!(
        "server_host_key_algorithms = {:?}",
        server_host_key_algorithms
    );

    let encrytion_algorithms_client_to_server = parse_name_list(&mut reader)?;
    debug!(
        "encrytion_algorithms_client_to_server = {:?}",
        encrytion_algorithms_client_to_server
    );

    let encrytion_algorithms_server_to_client = parse_name_list(&mut reader)?;
    debug!(
        "encrytion_algorithms_server_to_client = {:?}",
        encrytion_algorithms_server_to_client
    );

    let mac_algorithms_client_to_server = parse_name_list(&mut reader)?;
    debug!(
        "mac_algorithms_client_to_server = {:?}",
        mac_algorithms_client_to_server
    );

    let mac_algorithms_server_to_client = parse_name_list(&mut reader)?;
    debug!(
        "mac_algorithms_server_to_client = {:?}",
        mac_algorithms_server_to_client
    );

    let compression_algorithms_client_to_server = parse_name_list(&mut reader)?;
    debug!(
        "compression_algorithms_client_to_server = {:?}",
        compression_algorithms_client_to_server
    );

    let compression_algorithms_server_to_client = parse_name_list(&mut reader)?;
    debug!(
        "compression_algorithms_server_to_client = {:?}",
        compression_algorithms_server_to_client
    );

    let languages_client_to_server = parse_name_list(&mut reader)?;
    debug!(
        "languages_client_to_server = {:?}",
        languages_client_to_server
    );

    let languages_server_to_client = parse_name_list(&mut reader)?;
    debug!(
        "languages_server_to_client = {:?}",
        languages_server_to_client
    );

    if let Some(first_kex_packet_follows_u8) = reader.next() {
        let first_kex_packet_follows = u8_to_bool(*first_kex_packet_follows_u8)?;
        debug!("first_kex_packet_follows = {}", first_kex_packet_follows);
    } else {
        return packet_too_short("first_kex_packet_follows");
    }

    let _reserved = reader.take(4).collect::<Vec<&u8>>();

    debug!("--- END KEY EXCHANGE ---");
    Ok(())
}

fn packet_too_short(var_name: &str) -> Result<(), anyhow::Error> {
    Err(anyhow!(
        "Packet too short - '{}' could not be read",
        var_name
    ))
}

fn log_error(err: anyhow::Error) {
    error!("{}", err);
}
