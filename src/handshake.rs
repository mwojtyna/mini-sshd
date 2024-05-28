use std::{
    io::{BufRead, BufReader, Write},
    net::TcpStream,
};

use anyhow::{anyhow, Context, Result};
use const_format::formatcp;
use log::{debug, trace};
use num_traits::FromPrimitive;

use crate::{
    decoding::{decode_name_list, decode_packet, u8_to_bool},
    encoding::{bool_to_u8, encode_name_list, encode_packet},
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

    debug!("Decoding client algorithms...");
    let payload = decode_packet(stream).with_context(|| "Failed decoding key exchange packet")?;
    let mut reader = payload.into_iter();
    let reader = reader.by_ref();

    if let Some(msg_type) = reader.next() {
        if let Some(msg_type_enum) = MessageType::from_u8(msg_type) {
            trace!("msg_type = {:?}", msg_type_enum);
            if msg_type_enum != MessageType::SSH_MSG_KEXINIT {
                return Err(anyhow!("Expected SSH_MSG_KEXINIT, got {:?}", msg_type_enum));
            }
        } else {
            return Err(anyhow!("Failed casting msg_type"));
        }
    } else {
        return packet_too_short("msg_type");
    }

    let cookie = reader.take(16).collect::<Vec<u8>>();
    trace!("cookie = {:?}", cookie);

    let client_algorithms =
        decode_client_algorithms(reader).with_context(|| "Failed reading client algorithms")?;

    let server_algorithms_payload = encode_server_algorithms(&get_server_algorithms());
    let packet =
        encode_packet(&server_algorithms_payload).with_context(|| "Failed encoding packet")?;

    debug!("Sending server algorithms...");
    stream
        .write_all(&packet)
        .with_context(|| "Failed writing server algorithms packet")?;

    debug!("--- END KEY EXCHANGE ---");
    Ok(client_algorithms)
}

fn decode_client_algorithms(reader: &mut impl Iterator<Item = u8>) -> Result<Algorithms> {
    let kex_algorithms = decode_name_list(reader)?;
    debug!("kex_algorithms = {:?}", kex_algorithms);

    let server_host_key_algorithms = decode_name_list(reader)?;
    debug!(
        "server_host_key_algorithms = {:?}",
        server_host_key_algorithms
    );

    let encryption_algorithms_client_to_server = decode_name_list(reader)?;
    debug!(
        "encryption_algorithms_client_to_server = {:?}",
        encryption_algorithms_client_to_server
    );

    let encryption_algorithms_server_to_client = decode_name_list(reader)?;
    debug!(
        "encryption_algorithms_server_to_client = {:?}",
        encryption_algorithms_server_to_client
    );

    let mac_algorithms_client_to_server = decode_name_list(reader)?;
    debug!(
        "mac_algorithms_client_to_server = {:?}",
        mac_algorithms_client_to_server
    );

    let mac_algorithms_server_to_client = decode_name_list(reader)?;
    debug!(
        "mac_algorithms_server_to_client = {:?}",
        mac_algorithms_server_to_client
    );

    let compression_algorithms_client_to_server = decode_name_list(reader)?;
    debug!(
        "compression_algorithms_client_to_server = {:?}",
        compression_algorithms_client_to_server
    );

    let compression_algorithms_server_to_client = decode_name_list(reader)?;
    debug!(
        "compression_algorithms_server_to_client = {:?}",
        compression_algorithms_server_to_client
    );

    let languages_client_to_server = decode_name_list(reader)?;
    debug!(
        "languages_client_to_server = {:?}",
        languages_client_to_server
    );

    let languages_server_to_client = decode_name_list(reader)?;
    debug!(
        "languages_server_to_client = {:?}",
        languages_server_to_client
    );

    if let Some(first_kex_packet_follows_u8) = reader.next() {
        let first_kex_packet_follows = u8_to_bool(first_kex_packet_follows_u8)?;
        debug!("first_kex_packet_follows = {}", first_kex_packet_follows);
    } else {
        return packet_too_short("first_kex_packet_follows");
    }

    let _reserved = reader.take(4).collect::<Vec<u8>>();

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

fn encode_server_algorithms(algorithms: &Algorithms) -> Vec<u8> {
    let msg_type = vec![MessageType::SSH_MSG_KEXINIT as u8];
    let cookie = vec![0; 16]; // TODO: Random
    let kex_algorithms = encode_name_list(&algorithms.kex_algorithms);
    let server_host_key_algorithms = encode_name_list(&algorithms.server_host_key_algorithms);
    let encryption_algorithms_client_to_server =
        encode_name_list(&algorithms.encryption_algorithms_client_to_server);
    let encryption_algorithms_server_to_client =
        encode_name_list(&algorithms.encryption_algorithms_server_to_client);
    let mac_algorithms_client_to_server =
        encode_name_list(&algorithms.mac_algorithms_client_to_server);
    let mac_algorithms_server_to_client =
        encode_name_list(&algorithms.mac_algorithms_server_to_client);
    let compression_algorithms_client_to_server =
        encode_name_list(&algorithms.compression_algorithms_client_to_server);
    let compression_algorithms_server_to_client =
        encode_name_list(&algorithms.compression_algorithms_server_to_client);
    let languages_client_to_server = encode_name_list(&algorithms.languages_client_to_server);
    let languages_server_to_client = encode_name_list(&algorithms.languages_server_to_client);
    let first_kex_packet_follows = vec![bool_to_u8(false)];
    let reserved = vec![0; 4];

    [
        msg_type,
        cookie,
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
        first_kex_packet_follows,
        reserved,
    ]
    .concat()
}

fn get_server_algorithms() -> Algorithms {
    Algorithms {
        kex_algorithms: vec![],
        server_host_key_algorithms: vec![],
        encryption_algorithms_client_to_server: vec![],
        encryption_algorithms_server_to_client: vec![],
        mac_algorithms_client_to_server: vec![],
        mac_algorithms_server_to_client: vec![],
        compression_algorithms_client_to_server: vec!["none".to_owned()],
        compression_algorithms_server_to_client: vec!["none".to_owned()],
        languages_client_to_server: vec![],
        languages_server_to_client: vec![],
    }
}
