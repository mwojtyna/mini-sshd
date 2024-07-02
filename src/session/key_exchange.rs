use anyhow::{Context, Result};
use log::debug;
use openssl::bn::BigNum;

use crate::{
    decoding::PayloadReader,
    encoding::{
        encode_ec_public_key, encode_ec_signature, encode_mpint, encode_string, PacketBuilder,
    },
    hex_dump,
    types::MessageType,
    Session,
};

impl Session {
    // RFC 5656 § 4
    /// # Returns
    /// `(shared_secret, hash)`
    pub fn key_exchange(&mut self, reader: &mut PayloadReader) -> Result<(BigNum, Vec<u8>)> {
        debug!("--- BEGIN KEY EXCHANGE ---");

        // Client's public key
        let q_c = reader.next_string()?;

        let server_host_key_algorithm = &self.algorithms().server_host_key_algorithm;

        let host_key = &self
            .server_config
            .host_key
            .get(server_host_key_algorithm.name.as_str())
            .unwrap();

        // Server's public host key
        let k_s = encode_ec_public_key(
            &self.algorithms().server_host_key_algorithm,
            &host_key.public_key,
        )?;

        let (k, q_s) = self
            .crypto()
            .compute_shared_secret(&q_c)
            .context("Failed computing shared secret")?;

        let hash_data = concat_hash_data(
            self.kex().client_ident.as_bytes(),
            self.server_config.ident_string.as_bytes(),
            &self.kex().client_kexinit_payload,
            &self.kex().server_kexinit_payload,
            &k_s,
            &q_c,
            &q_s,
            &k,
        )?;

        let (hash, signed_exchange_hash) = self
            .crypto()
            .ec_hash_and_sign(&host_key.ec_pair, &hash_data)
            .context("Failed to hash and sign")?;

        let signature_enc = encode_ec_signature(server_host_key_algorithm, &signed_exchange_hash)?;

        let packet = PacketBuilder::new(MessageType::SSH_MSG_KEX_ECDH_REPLY, self)
            .write_string(&k_s)
            .write_string(&q_s)
            .write_string(&signature_enc)
            .build()?;
        self.send_packet(&packet)?;

        debug!("--- END KEY EXCHANGE ---");
        Ok((k, hash))
    }
}

#[allow(clippy::too_many_arguments)]
fn concat_hash_data(
    v_c: &[u8],
    v_s: &[u8],
    i_c: &[u8],
    i_s: &[u8],
    k_s: &[u8],
    q_c: &[u8],
    q_s: &[u8],
    k: &BigNum,
) -> Result<Vec<u8>> {
    hex_dump!(&v_c);
    hex_dump!(&v_s);
    hex_dump!(&i_c);
    hex_dump!(&i_s);
    hex_dump!(&k_s);
    hex_dump!(&q_c);
    hex_dump!(&q_s);
    hex_dump!(&k.to_vec());

    let v_c = encode_string(v_c);
    let v_s = encode_string(v_s);
    let i_c = encode_string(i_c);
    let i_s = encode_string(i_s);
    let k_s = encode_string(k_s);
    let q_c = encode_string(q_c);
    let q_s = encode_string(q_s);
    let k = encode_mpint(k);

    Ok([v_c, v_s, i_c, i_s, k_s, q_c, q_s, k].concat())
}
