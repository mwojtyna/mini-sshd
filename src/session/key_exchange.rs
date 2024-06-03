use anyhow::{Context, Result};
use log::debug;

use crate::{
    crypto::compute_shared_secret,
    decoding::{decode_string, DecodedPacket},
    encoding::{encode_packet, encode_string},
    types::MessageType,
    Session,
};

impl Session {
    // RFC 5656 § 4
    pub(super) fn key_exchange(&mut self, packet: DecodedPacket) -> Result<()> {
        debug!("--- BEGIN KEY EXCHANGE ---");

        // TODO: Validate q_c

        // Client's public key
        let q_c = decode_string(&mut packet.payload.into_iter())?;
        if cfg!(debug_assertions) {
            debug!("q_c = {:?}, length = {}", q_c, q_c.len());
        }

        // Server's public host key
        let k_s = self.server_config.host_key.raw_public_key()?;
        if cfg!(debug_assertions) {
            debug!("k_s = {:?}, length = {}", k_s, k_s.len());
        }

        let shared_secret =
            compute_shared_secret(&q_c).context("Failed computing shared secret")?;

        // Server's ephemeral public key octet string
        let q_s = shared_secret.eph_public_key;
        if cfg!(debug_assertions) {
            debug!("q_s = {:?}, length = {}", q_s, q_s.len());
        }

        let k = shared_secret.secret;
        if cfg!(debug_assertions) {
            debug!("shared_secret = {:?}, length = {}", k, k.len());
        }

        let payload = [
            vec![MessageType::SSH_MSG_KEX_ECDH_REPLY as u8],
            encode_string(&k_s),
            encode_string(&q_s),
            encode_string(&[]), // TODO: exchange hash signature
        ]
        .concat();

        let packet = encode_packet(&payload)?;
        self.send_packet(&packet)?;

        debug!("--- END KEY EXCHANGE ---");
        Ok(())
    }
}
