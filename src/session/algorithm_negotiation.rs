use std::{collections::HashSet, fmt::Debug};

use anyhow::{anyhow, Context, Result};
use indexmap::IndexMap;
use log::{debug, trace};

use crate::{
    crypto::Crypto,
    decoding::{packet_too_short, u8_to_bool, DecodedPacket, PayloadReader},
    encoding::PacketBuilder,
    session::Session,
    types::{
        CompressionAlgorithmDetails, EncryptionAlgorithmDetails, HmacAlgorithmDetails,
        HostKeyAlgorithmDetails, KexAlgorithm, KexAlgorithmDetails, MessageType,
    },
};

type AlgorithmsCollection<D> = IndexMap<&'static str, D>;

#[derive(Default, Clone)]
/// List of preferred algorithms in order of preference
pub struct ServerAlgorithms {
    pub kex_algorithms: AlgorithmsCollection<KexAlgorithmDetails>,
    pub server_host_key_algorithms: AlgorithmsCollection<HostKeyAlgorithmDetails>,
    pub client_host_key_algorithms: AlgorithmsCollection<HostKeyAlgorithmDetails>,
    pub encryption_algorithms_client_to_server: AlgorithmsCollection<EncryptionAlgorithmDetails>,
    pub encryption_algorithms_server_to_client: AlgorithmsCollection<EncryptionAlgorithmDetails>,
    pub mac_algorithms_client_to_server: AlgorithmsCollection<HmacAlgorithmDetails>,
    pub mac_algorithms_server_to_client: AlgorithmsCollection<HmacAlgorithmDetails>,
    pub compression_algorithms_client_to_server:
        AlgorithmsCollection<Option<CompressionAlgorithmDetails>>,
    pub compression_algorithms_server_to_client:
        AlgorithmsCollection<Option<CompressionAlgorithmDetails>>,
    pub languages_client_to_server: Vec<&'static str>,
    pub languages_server_to_client: Vec<&'static str>,
}

impl Debug for ServerAlgorithms {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!(
            "ServerAlgorithms {{\nkex_algorithms: {:#?},\nserver_host_key_algorithms: {:#?},\nencryption_algorithms_client_to_server: {:#?},\nencryption_algorithms_server_to_client: {:#?},\nmac_algorithms_client_to_server: {:#?},\nmac_algorithms_server_to_client: {:#?},\ncompression_algorithms_client_to_server: {:#?},\ncompression_algorithms_server_to_client: {:#?},\nlanguages_client_to_server: {:#?},\nlanguages_server_to_client: {:#?}\n}}",
            self.kex_algorithms.keys(),
            self.server_host_key_algorithms.keys(),
            self.encryption_algorithms_client_to_server.keys(),
            self.encryption_algorithms_server_to_client.keys(),
            self.mac_algorithms_client_to_server.keys(),
            self.mac_algorithms_server_to_client.keys(),
            self.compression_algorithms_client_to_server.keys(),
            self.compression_algorithms_server_to_client.keys(),
            self.languages_client_to_server,
            self.languages_server_to_client,
        ))
    }
}

#[derive(Debug)]
pub struct ClientAlgorithms {
    pub kex_algorithms: Vec<String>,
    pub server_host_key_algorithms: Vec<String>,
    pub encryption_algorithms_client_to_server: Vec<String>,
    pub encryption_algorithms_server_to_client: Vec<String>,
    pub mac_algorithms_client_to_server: Vec<String>,
    pub mac_algorithms_server_to_client: Vec<String>,
    pub compression_algorithms_client_to_server: Vec<String>,
    pub compression_algorithms_server_to_client: Vec<String>,
    #[allow(dead_code)]
    pub languages_client_to_server: Vec<String>,
    #[allow(dead_code)]
    pub languages_server_to_client: Vec<String>,
}

#[derive(Clone)]
pub struct Algorithm<D> {
    pub name: String,
    pub details: D,
}

impl<D> Algorithm<D> {
    pub fn new(name: String, details: D) -> Self {
        Self { name, details }
    }
}

impl<D> Debug for Algorithm<D> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("\"{}\"", &self.name))
    }
}

#[derive(Debug, Clone)]
/// Agreed upon algorithms
pub struct Algorithms {
    pub kex_algorithm: Algorithm<KexAlgorithmDetails>,
    pub server_host_key_algorithm: Algorithm<HostKeyAlgorithmDetails>,
    pub encryption_algorithms_client_to_server: Algorithm<EncryptionAlgorithmDetails>,
    pub encryption_algorithms_server_to_client: Algorithm<EncryptionAlgorithmDetails>,
    pub mac_algorithms_client_to_server: Algorithm<HmacAlgorithmDetails>,
    pub mac_algorithms_server_to_client: Algorithm<HmacAlgorithmDetails>,
    #[allow(dead_code)]
    pub compression_algorithms_client_to_server: Algorithm<Option<CompressionAlgorithmDetails>>,
    #[allow(dead_code)]
    pub compression_algorithms_server_to_client: Algorithm<Option<CompressionAlgorithmDetails>>,
    #[allow(dead_code)]
    pub languages_client_to_server: String,
    #[allow(dead_code)]
    pub languages_server_to_client: String,
}

impl Session<'_> {
    // RFC 4253 § 7
    pub fn algorithm_negotiation(
        &mut self,
        packet: &DecodedPacket,
        reader: &mut PayloadReader,
    ) -> Result<Algorithms> {
        debug!("--- BEGIN ALGORITHM NEGOTIATION ---");
        packet
            .payload_with_msg_type()
            .clone_into(&mut self.kex.client_kexinit_payload);

        debug!("Decoding client algorithms...");

        let cookie = reader.next_n_bytes(16);
        trace!("cookie = {:02x?}", cookie);

        let client_algorithms =
            Self::decode_client_algorithms(reader).context("Failed reading client algorithms")?;

        let (server_algorithms_payload, server_algorithms_packet) =
            self.encode_server_algorithms(&self.server_config.algorithms)?;

        server_algorithms_payload.clone_into(&mut self.kex.server_kexinit_payload);

        debug!("Sending server algorithms...");
        debug!("server_algorithms = {:#?}", &self.server_config.algorithms);
        self.send_packet(&server_algorithms_packet)
            .context("Failed writing server algorithms packet")?;

        let negotiated =
            self.negotiate_algorithms(&client_algorithms, &self.server_config.algorithms)?;
        debug!("negotiated_algorithms = {:#?}", negotiated);

        debug!("--- END ALGORITHM NEGOTIATION ---");
        Ok(negotiated)
    }

    fn algos_to_names<V>(algo: &AlgorithmsCollection<V>) -> Vec<&str> {
        algo.keys().copied().collect()
    }
    fn encode_server_algorithms(
        &self,
        algorithms: &ServerAlgorithms,
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        let cookie = Crypto::generate_random_array(16)?;
        let first_kex_packet_follows = false;
        let reserved = vec![0; 4];

        let payload_packet = PacketBuilder::new(MessageType::SSH_MSG_KEXINIT, self)
            .write_bytes(&cookie)
            .write_name_list(&Self::algos_to_names(&algorithms.kex_algorithms))
            .write_name_list(&Self::algos_to_names(
                &algorithms.server_host_key_algorithms,
            ))
            .write_name_list(&Self::algos_to_names(
                &algorithms.encryption_algorithms_client_to_server,
            ))
            .write_name_list(&Self::algos_to_names(
                &algorithms.encryption_algorithms_server_to_client,
            ))
            .write_name_list(&Self::algos_to_names(
                &algorithms.mac_algorithms_client_to_server,
            ))
            .write_name_list(&Self::algos_to_names(
                &algorithms.mac_algorithms_server_to_client,
            ))
            .write_name_list(&Self::algos_to_names(
                &algorithms.compression_algorithms_client_to_server,
            ))
            .write_name_list(&Self::algos_to_names(
                &algorithms.compression_algorithms_server_to_client,
            ))
            .write_name_list(&algorithms.languages_client_to_server)
            .write_name_list(&algorithms.languages_server_to_client)
            .write_bool(first_kex_packet_follows)
            .write_bytes(&reserved)
            .build_get_payload()?;

        Ok(payload_packet)
    }

    fn decode_client_algorithms(reader: &mut PayloadReader) -> Result<ClientAlgorithms> {
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

        let client_algorithms = ClientAlgorithms {
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

    fn negotiate_algorithms(
        &mut self,
        client_algorithms: &ClientAlgorithms,
        server_algorithms: &ServerAlgorithms,
    ) -> Result<Algorithms> {
        if client_algorithms
            .kex_algorithms
            .contains(&KexAlgorithm::EXT_INFO_C.to_owned())
        {
            self.kex.ext_info_c = true;
        }

        let kex_algorithm_name = self
            .negotiate_algorithm(
                &client_algorithms.kex_algorithms,
                &server_algorithms.kex_algorithms,
            )?
            .clone();
        let kex_algorithm = server_algorithms
            .kex_algorithms
            .get(&kex_algorithm_name.as_str())
            .context("Could not find kex_algorithm")?
            .clone();

        let server_host_key_algorithm_name = self
            .negotiate_algorithm(
                &client_algorithms.server_host_key_algorithms,
                &server_algorithms.server_host_key_algorithms,
            )?
            .clone();
        let server_host_key_algorithm = server_algorithms
            .server_host_key_algorithms
            .get(&server_host_key_algorithm_name.as_str())
            .context("Could not find server_host_key_algorithm")?
            .clone();

        let encryption_algorithms_client_to_server_name = self
            .negotiate_algorithm(
                &client_algorithms.encryption_algorithms_client_to_server,
                &server_algorithms.encryption_algorithms_client_to_server,
            )?
            .clone();
        let encryption_algorithms_client_to_server = server_algorithms
            .encryption_algorithms_client_to_server
            .get(&encryption_algorithms_client_to_server_name.as_str())
            .context("Could not find encryption_algorithms_client_to_server")?
            .clone();

        let encryption_algorithms_server_to_client_name = self
            .negotiate_algorithm(
                &client_algorithms.encryption_algorithms_server_to_client,
                &server_algorithms.encryption_algorithms_server_to_client,
            )?
            .clone();
        let encryption_algorithms_server_to_client = server_algorithms
            .encryption_algorithms_server_to_client
            .get(&encryption_algorithms_server_to_client_name.as_str())
            .context("Could not find encryption_algorithms_server_to_client")?
            .clone();

        let mac_algorithms_client_to_server_name = self
            .negotiate_algorithm(
                &client_algorithms.mac_algorithms_client_to_server,
                &server_algorithms.mac_algorithms_client_to_server,
            )?
            .clone();
        let mac_algorithms_client_to_server = server_algorithms
            .mac_algorithms_client_to_server
            .get(&mac_algorithms_client_to_server_name.as_str())
            .context("Could not find mac_algorithms_client_to_server")?
            .clone();

        let mac_algorithms_server_to_client_name = self
            .negotiate_algorithm(
                &client_algorithms.mac_algorithms_server_to_client,
                &server_algorithms.mac_algorithms_server_to_client,
            )?
            .clone();
        let mac_algorithms_server_to_client = server_algorithms
            .mac_algorithms_server_to_client
            .get(&mac_algorithms_server_to_client_name.as_str())
            .context("Could not find mac_algorithms_server_to_client")?
            .clone();

        let compression_algorithms_client_to_server_name = self.negotiate_algorithm(
            &client_algorithms.compression_algorithms_client_to_server,
            &server_algorithms.compression_algorithms_client_to_server,
        )?;
        let compression_algorithms_client_to_server = server_algorithms
            .compression_algorithms_client_to_server
            .get(&compression_algorithms_client_to_server_name.as_str())
            .context("Could not find compression_algorithms_server_to_client")?;

        let compression_algorithms_server_to_client_name = self.negotiate_algorithm(
            &client_algorithms.compression_algorithms_server_to_client,
            &server_algorithms.compression_algorithms_server_to_client,
        )?;
        let compression_algorithms_server_to_client = server_algorithms
            .compression_algorithms_server_to_client
            .get(&compression_algorithms_server_to_client_name.as_str())
            .context("Could not find compression_algorithms_server_to_client")?;

        // let languages_client_to_server = Self::negotiate_algorithm(
        //     &client_algorithms.languages_client_to_server,
        //     server_algorithms.languages_client_to_server,
        // )?;
        // let languages_server_to_client = Self::negotiate_algorithm(
        //     &client_algorithms.languages_server_to_client,
        //     server_algorithms.languages_server_to_client,
        // )?;

        Ok(Algorithms {
            kex_algorithm: Algorithm::new(kex_algorithm_name, kex_algorithm),
            server_host_key_algorithm: Algorithm::new(
                server_host_key_algorithm_name,
                server_host_key_algorithm,
            ),
            encryption_algorithms_client_to_server: Algorithm::new(
                encryption_algorithms_client_to_server_name,
                encryption_algorithms_client_to_server,
            ),
            encryption_algorithms_server_to_client: Algorithm::new(
                encryption_algorithms_server_to_client_name,
                encryption_algorithms_server_to_client,
            ),
            mac_algorithms_client_to_server: Algorithm::new(
                mac_algorithms_client_to_server_name,
                mac_algorithms_client_to_server,
            ),
            mac_algorithms_server_to_client: Algorithm::new(
                mac_algorithms_server_to_client_name,
                mac_algorithms_server_to_client,
            ),
            compression_algorithms_client_to_server: Algorithm::new(
                compression_algorithms_client_to_server_name.clone(),
                compression_algorithms_client_to_server.clone(),
            ),
            compression_algorithms_server_to_client: Algorithm::new(
                compression_algorithms_server_to_client_name.clone(),
                compression_algorithms_server_to_client.clone(),
            ),
            languages_client_to_server: "".to_string(),
            languages_server_to_client: "".to_string(),
        })
    }

    // RFC 4253 § 7.1
    fn negotiate_algorithm<V>(
        &mut self,
        client_algorithms: &[String],
        server_algorithms: &AlgorithmsCollection<V>,
    ) -> Result<String> {
        let client_set: HashSet<String> = HashSet::from_iter(client_algorithms.iter().cloned());
        let server_set: HashSet<String> =
            HashSet::from_iter(server_algorithms.keys().cloned().map(|k| k.to_owned()));

        let intersection: HashSet<String> = client_set.intersection(&server_set).cloned().collect();

        if intersection.is_empty() {
            Err(anyhow!(
                "Could not negotiate algorithms: client_algorithms={:?}, server_algorithms={:?}",
                client_algorithms,
                server_algorithms.keys(),
            ))
        } else {
            let preffered_algorithm = intersection
                .into_iter()
                .min_by_key(|intersection_algo| {
                    client_algorithms
                        .iter()
                        .position(|server_algo| server_algo == intersection_algo)
                        .unwrap()
                })
                .unwrap();

            Ok(preffered_algorithm)
        }
    }
}
