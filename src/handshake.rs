use std::{
    io::{BufRead, BufReader, Write},
    net::TcpStream,
};

use anyhow::{anyhow, Context, Result};
use const_format::formatcp;
use log::debug;
use num_traits::FromPrimitive;

use crate::{
    parsers::{parse_name_list, parse_packet, u8_to_bool},
    types::MessageType,
    utils::packet_too_short,
};

pub struct Algorithms {
    pub kex_algorithms: Vec<String>,
    pub server_host_key_algorithms: Vec<String>,
    pub encryption_algorithms_client_to_server: Vec<String>,
    pub encryption_algorithms_server_to_client: Vec<String>,
    pub mac_algorithms_client_to_server: Vec<String>,
    pub mac_algorithms_server_to_client: Vec<String>,
    pub compression_algorithms_client_to_server: Vec<String>,
    pub compression_algorithms_server_to_client: Vec<String>,
    pub languages_client_to_server: Vec<String>,
    pub languages_server_to_client: Vec<String>,
}

const VERSION: &str = env!("CARGO_PKG_VERSION");
const IDENT_STRING: &str = formatcp!("SSH-2.0-minisshd_{}\r\n", VERSION);
const SERVER_ALGORITHMS: Algorithms = Algorithms {
    kex_algorithms: vec![],
    server_host_key_algorithms: vec![],
    encryption_algorithms_client_to_server: vec![],
    encryption_algorithms_server_to_client: vec![],
    mac_algorithms_client_to_server: vec![],
    mac_algorithms_server_to_client: vec![],
    compression_algorithms_client_to_server: vec![],
    compression_algorithms_server_to_client: vec![],
    languages_client_to_server: vec![],
    languages_server_to_client: vec![],
};

// RFC 4253 § 4.2
pub fn ident_exchange(stream: &mut TcpStream) -> Result<()> {
    debug!("--- BEGIN IDENTIFICATION EXCHANGE ---");
    stream.write_all(IDENT_STRING.as_bytes())?;

    let mut reader = BufReader::new(stream);
    let mut client_ident = String::new();
    reader
        .read_line(&mut client_ident)
        .with_context(|| "Failed reading client_ident")?;
    client_ident = client_ident.lines().next().unwrap().to_string();
    debug!("client = {:?}", client_ident);

    debug!("--- END IDENTIFICATION EXCHANGE ---");
    Ok(())
}

// RFC 4253 § 7
pub fn key_exchange(stream: &mut TcpStream) -> Result<Algorithms> {
    debug!("--- BEGIN KEY EXCHANGE ---");
    let payload = parse_packet(stream)?;
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

    let encryption_algorithms_client_to_server = parse_name_list(&mut reader)?;
    debug!(
        "encryption_algorithms_client_to_server = {:?}",
        encryption_algorithms_client_to_server
    );

    let encryption_algorithms_server_to_client = parse_name_list(&mut reader)?;
    debug!(
        "encryption_algorithms_server_to_client = {:?}",
        encryption_algorithms_server_to_client
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
    Ok(Algorithms {
        kex_algorithms,
        server_host_key_algorithms,
        encryption_algorithms_client_to_server,
        encryption_algorithms_server_to_client,
        mac_algorithms_client_to_server,
        mac_algorithms_server_to_client,
        compression_algorithms_client_to_server,
        compression_algorithms_server_to_client,
        languages_client_to_server,
        languages_server_to_client,
    })
}
