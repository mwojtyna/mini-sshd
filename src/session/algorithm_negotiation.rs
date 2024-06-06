use std::collections::HashSet;

use anyhow::{anyhow, Context, Result};
use log::{debug, trace};

use crate::{
    crypto::generate_random_array,
    decoding::{packet_too_short, u8_to_bool, DecodedPacket, PayloadReader},
    encoding::PacketBuilder,
    session::Session,
    types::MessageType,
};

#[derive(Debug, Default, Clone)]
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
    pub(super) fn algorithm_negotiation(
        &mut self,
        packet: &DecodedPacket,
        reader: &mut PayloadReader,
    ) -> Result<Algorithms> {
        debug!("--- BEGIN ALGORITHM NEGOTIATION ---");
        packet
            .payload_with_msg_type()
            .clone_into(&mut self.client_kexinit_payload);

        debug!("Decoding client algorithms...");

        let cookie = reader.next_n_bytes(16);
        trace!("cookie = {:?}", cookie);

        let client_algorithms =
            decode_client_algorithms(reader).context("Failed reading client algorithms")?;

        let (server_algorithms_payload, server_algorithms_packet) =
            encode_server_algorithms(&self.server_config.algorithms)?;

        server_algorithms_payload.clone_into(&mut self.server_kexinit_payload);

        debug!("Sending server algorithms...");
        debug!("server_algorithms = {:#?}", &self.server_config.algorithms);
        self.send_packet(&server_algorithms_packet)
            .context("Failed writing server algorithms packet")?;

        let negotiated = negotiate_algorithms(&client_algorithms, &self.server_config.algorithms)?;
        debug!("negotiated_algorithms = {:#?}", negotiated);

        debug!("--- END ALGORITHM NEGOTIATION ---");
        Ok(negotiated)
    }
}

fn decode_client_algorithms(reader: &mut PayloadReader) -> Result<AlgorithmNegotiation> {
    let kex_algorithms = reader.next_name_list()?;
    let server_host_key_algorithms = reader.next_name_list()?;
    let encryption_algorithms_client_to_server = reader.next_name_list()?;
    let encryption_algorithms_server_to_client = reader.next_name_list()?;
    let mac_algorithms_client_to_server = reader.next_name_list()?;
    let mac_algorithms_server_to_client = reader.next_name_list()?;
    let compression_algorithms_client_to_server = reader.next_name_list()?;
    let compression_algorithms_server_to_client = reader.next_name_list()?;
    let languages_client_to_server = reader.next_name_list()?;
    let languages_server_to_client = reader.next_name_list()?;

    if let Some(first_kex_packet_follows_u8) = reader.next_byte() {
        let first_kex_packet_follows = u8_to_bool(first_kex_packet_follows_u8)?;
        debug!("first_kex_packet_follows = {}", first_kex_packet_follows);
    } else {
        return packet_too_short("first_kex_packet_follows");
    }

    let _reserved = reader.next_n_bytes(4);

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

fn encode_server_algorithms(algorithms: &AlgorithmNegotiation) -> Result<(Vec<u8>, Vec<u8>)> {
    let cookie = generate_random_array(16)?;
    let first_kex_packet_follows = false;
    let reserved = vec![0; 4];

    let payload_packet = PacketBuilder::new(MessageType::SSH_MSG_KEXINIT)
        .write_bytes(&cookie)
        .write_name_list(&algorithms.kex_algorithms)
        .write_name_list(&algorithms.server_host_key_algorithms)
        .write_name_list(&algorithms.encryption_algorithms_client_to_server)
        .write_name_list(&algorithms.encryption_algorithms_server_to_client)
        .write_name_list(&algorithms.mac_algorithms_client_to_server)
        .write_name_list(&algorithms.mac_algorithms_server_to_client)
        .write_name_list(&algorithms.compression_algorithms_client_to_server)
        .write_name_list(&algorithms.compression_algorithms_server_to_client)
        .write_name_list(&algorithms.languages_client_to_server)
        .write_name_list(&algorithms.languages_server_to_client)
        .write_bool(first_kex_packet_follows)
        .write_bytes(&reserved)
        .build_get_payload()?;

    Ok(payload_packet)
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
