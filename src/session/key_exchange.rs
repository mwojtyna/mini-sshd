use std::collections::HashSet;

use anyhow::{anyhow, Context, Result};
use log::{debug, trace};

use crate::{
    crypto::random_array,
    decoding::{decode_name_list, decode_packet, packet_too_short, u8_to_MessageType, u8_to_bool},
    encoding::{bool_to_u8, encode_name_list, encode_packet},
    session::Session,
    types::MessageType,
};

#[derive(Debug, Default)]
/// List of preferred algorithms in order of preference
pub struct AlgorithmNegotiation {
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

#[derive(Debug, Default)]
/// Agreed upon algorithms
pub struct Algorithms {
    pub kex_algorithm: String,
    pub server_host_key_algorithm: String,
    pub encryption_algorithms_client_to_server: String,
    pub encryption_algorithms_server_to_client: String,
    pub mac_algorithms_client_to_server: String,
    pub mac_algorithms_server_to_client: String,
    pub compression_algorithms_client_to_server: String,
    pub compression_algorithms_server_to_client: String,
    pub languages_client_to_server: String,
    pub languages_server_to_client: String,
}

impl Session {
    // RFC 4253 § 7
    pub(super) fn key_exchange(&mut self) -> Result<Algorithms> {
        debug!("--- BEGIN KEY EXCHANGE ---");

        debug!("Decoding client algorithms...");
        let payload = decode_packet(&self.stream)
            .context("Failed decoding key exchange packet")?
            .payload;
        let mut reader = payload.into_iter();
        let reader = reader.by_ref();

        if let Some(msg_type_u8) = reader.next() {
            let msg_type = u8_to_MessageType(msg_type_u8)?;
            if msg_type != MessageType::SSH_MSG_KEXINIT {
                return Err(anyhow!("Expected SSH_MSG_KEXINIT, got {:?}", msg_type));
            }
        } else {
            return packet_too_short("msg_type");
        }

        let cookie = reader.take(16).collect::<Vec<u8>>();
        trace!("cookie = {:?}", cookie);

        let client_algorithms =
            decode_client_algorithms(reader).context("Failed reading client algorithms")?;

        let server_algorithms = get_server_algorithms();
        let server_algorithms_payload = encode_server_algorithms(&server_algorithms);
        let server_algorithms_packet =
            encode_packet(&server_algorithms_payload?).context("Failed encoding packet")?;

        debug!("Sending server algorithms...");
        debug!("server_algorithms = {:#?}", server_algorithms);
        self.send_packet(&server_algorithms_packet)
            .context("Failed writing server algorithms packet")?;

        let negotiated = negotiate_algorithms(&client_algorithms, &server_algorithms)?;
        debug!("negotiated_algorithms = {:#?}", negotiated);

        debug!("--- END KEY EXCHANGE ---");
        Ok(negotiated)
    }
}

fn decode_client_algorithms(reader: &mut impl Iterator<Item = u8>) -> Result<AlgorithmNegotiation> {
    let kex_algorithms = decode_name_list(reader)?;
    let server_host_key_algorithms = decode_name_list(reader)?;
    let encryption_algorithms_client_to_server = decode_name_list(reader)?;
    let encryption_algorithms_server_to_client = decode_name_list(reader)?;
    let mac_algorithms_client_to_server = decode_name_list(reader)?;
    let mac_algorithms_server_to_client = decode_name_list(reader)?;
    let compression_algorithms_client_to_server = decode_name_list(reader)?;
    let compression_algorithms_server_to_client = decode_name_list(reader)?;
    let languages_client_to_server = decode_name_list(reader)?;
    let languages_server_to_client = decode_name_list(reader)?;

    if let Some(first_kex_packet_follows_u8) = reader.next() {
        let first_kex_packet_follows = u8_to_bool(first_kex_packet_follows_u8)?;
        debug!("first_kex_packet_follows = {}", first_kex_packet_follows);
    } else {
        return packet_too_short("first_kex_packet_follows");
    }

    let _reserved = reader.take(4).collect::<Vec<u8>>();

    let client_algorithms = AlgorithmNegotiation {
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
    };
    debug!("client_algorithms = {:#?}", client_algorithms);

    Ok(client_algorithms)
}

fn encode_server_algorithms(algorithms: &AlgorithmNegotiation) -> Result<Vec<u8>> {
    let msg_type = vec![MessageType::SSH_MSG_KEXINIT as u8];
    let cookie = random_array(16)?;
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

    Ok([
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
    .concat())
}

fn negotiate_algorithms(
    client_algorithms: &AlgorithmNegotiation,
    server_algorithms: &AlgorithmNegotiation,
) -> Result<Algorithms> {
    let kex_algorithm = negotiate_algorithm(
        &client_algorithms.kex_algorithms,
        &server_algorithms.kex_algorithms,
    )?;
    let server_host_key_algorithm = negotiate_algorithm(
        &client_algorithms.server_host_key_algorithms,
        &server_algorithms.server_host_key_algorithms,
    )?;
    let encryption_algorithms_client_to_server = negotiate_algorithm(
        &client_algorithms.encryption_algorithms_client_to_server,
        &server_algorithms.encryption_algorithms_client_to_server,
    )?;
    let encryption_algorithms_server_to_client = negotiate_algorithm(
        &client_algorithms.encryption_algorithms_server_to_client,
        &server_algorithms.encryption_algorithms_server_to_client,
    )?;
    let mac_algorithms_client_to_server = negotiate_algorithm(
        &client_algorithms.mac_algorithms_client_to_server,
        &server_algorithms.mac_algorithms_client_to_server,
    )?;
    let mac_algorithms_server_to_client = negotiate_algorithm(
        &client_algorithms.mac_algorithms_server_to_client,
        &server_algorithms.mac_algorithms_server_to_client,
    )?;
    let compression_algorithms_client_to_server = negotiate_algorithm(
        &client_algorithms.compression_algorithms_client_to_server,
        &server_algorithms.compression_algorithms_client_to_server,
    )?;
    let compression_algorithms_server_to_client = negotiate_algorithm(
        &client_algorithms.compression_algorithms_server_to_client,
        &server_algorithms.compression_algorithms_server_to_client,
    )?;
    let languages_client_to_server = negotiate_algorithm(
        &client_algorithms.languages_client_to_server,
        &server_algorithms.languages_client_to_server,
    )?;
    let languages_server_to_client = negotiate_algorithm(
        &client_algorithms.languages_server_to_client,
        &server_algorithms.languages_server_to_client,
    )?;

    Ok(Algorithms {
        kex_algorithm,
        server_host_key_algorithm,
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

// RFC 4253 § 7.1
fn negotiate_algorithm(
    client_algorithms: &[String],
    server_algorithms: &[String],
) -> Result<String> {
    let client_set: HashSet<String> = HashSet::from_iter(client_algorithms.iter().cloned());
    let server_set: HashSet<String> = HashSet::from_iter(server_algorithms.iter().cloned());
    let intersection: HashSet<String> = client_set.intersection(&server_set).cloned().collect();

    if intersection.is_empty() {
        Err(anyhow!(
            "Could not negotiate algorithms: client_algorithms={:?}, server_algorithms={:?}",
            client_algorithms,
            server_algorithms,
        ))
    } else {
        let preffered_algorithm = intersection
            .into_iter()
            .min_by_key(|intersection_algo| {
                server_algorithms
                    .iter()
                    .position(|server_algo| server_algo == intersection_algo)
                    .unwrap()
            })
            .unwrap();

        Ok(preffered_algorithm)
    }
}

fn get_server_algorithms() -> AlgorithmNegotiation {
    AlgorithmNegotiation {
        // RFC 9142 § 4
        kex_algorithms: vec!["diffie-hellman-group14-sha256".to_owned()],

        server_host_key_algorithms: vec!["ssh-ed25519".to_owned()],
        encryption_algorithms_client_to_server: vec!["aes128-ctr".to_owned()],
        encryption_algorithms_server_to_client: vec!["aes128-ctr".to_owned()],

        // RFC 6668 § 2
        mac_algorithms_client_to_server: vec!["hmac-sha2-256".to_owned()],
        mac_algorithms_server_to_client: vec!["hmac-sha2-256".to_owned()],

        compression_algorithms_client_to_server: vec!["none".to_owned()],
        compression_algorithms_server_to_client: vec!["none".to_owned()],
        languages_client_to_server: vec!["".to_owned()],
        languages_server_to_client: vec!["".to_owned()],
    }
}
