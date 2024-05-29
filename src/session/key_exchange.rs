use anyhow::{anyhow, Context, Result};
use log::{debug, trace};

use crate::{
    decoding::{decode_name_list, decode_packet, packet_too_short, u8_to_MessageType, u8_to_bool},
    encoding::{bool_to_u8, encode_name_list, encode_packet, random_array},
    session::Session,
    types::MessageType,
};

#[derive(Debug, Default)]
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

        let client_algorithms = self
            .decode_client_algorithms(reader)
            .context("Failed reading client algorithms")?;

        let server_algorithms = &Self::get_server_algorithms();
        let server_algorithms_payload = self.encode_server_algorithms(server_algorithms);
        let packet =
            encode_packet(&server_algorithms_payload?).context("Failed encoding packet")?;

        debug!("Sending server algorithms...");
        debug!("server_algorithms = {:#?}", server_algorithms);
        self.send_packet(&packet)
            .context("Failed writing server algorithms packet")?;

        debug!("--- END KEY EXCHANGE ---");
        Ok(client_algorithms)
    }

    fn decode_client_algorithms(
        &mut self,
        reader: &mut impl Iterator<Item = u8>,
    ) -> Result<Algorithms> {
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

        let client_algorithms = Algorithms {
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

    fn encode_server_algorithms(&mut self, algorithms: &Algorithms) -> Result<Vec<u8>> {
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

    fn get_server_algorithms() -> Algorithms {
        Algorithms {
            kex_algorithms: vec!["sntrup761x25519-sha512@openssh.com".to_owned()],
            server_host_key_algorithms: vec!["ssh-ed25519-cert-v01@openssh.com".to_owned()],
            encryption_algorithms_client_to_server: vec!["chacha20-poly1305@openssh.com".to_owned()],
            encryption_algorithms_server_to_client: vec!["chacha20-poly1305@openssh.com".to_owned()],
            mac_algorithms_client_to_server: vec!["hmac-sha2-256-etm@openssh.com".to_owned()],
            mac_algorithms_server_to_client: vec!["hmac-sha2-256-etm@openssh.com".to_owned()],
            compression_algorithms_client_to_server: vec!["none".to_owned()],
            compression_algorithms_server_to_client: vec!["none".to_owned()],
            languages_client_to_server: vec!["".to_owned()],
            languages_server_to_client: vec!["".to_owned()],
        }
    }
}
