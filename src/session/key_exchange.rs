use anyhow::{Context, Result};
use log::debug;
use openssl::{bn::BigNum, ecdsa::EcdsaSigRef};

use crate::{
    crypto::{compute_shared_secret, hash_and_sign, ComputeSharedSecretResult},
    decoding::{decode_string, DecodedPacket},
    encoding::{encode_mpint, encode_packet, encode_string},
    types::MessageType,
    Session,
};

impl Session {
    // RFC 5656 § 4
    pub(super) fn key_exchange(&mut self, packet: DecodedPacket) -> Result<()> {
        debug!("--- BEGIN KEY EXCHANGE ---");

        // Client's public key
        let q_c = decode_string(&mut packet.payload().into_iter())?;

        // Server's public host key
        let k_s = encode_public_key("nistp256", self.server_config.host_key.public_key());

        let ComputeSharedSecretResult {
            secret: k,
            eph_public_key: q_s,
            hash_type,
        } = compute_shared_secret(&q_c).context("Failed computing shared secret")?;

        let hash_data = concat_hash_data(
            self.client_ident.as_bytes(),
            self.server_config.ident_string.as_bytes(),
            &self.client_kexinit_payload,
            &self.server_kexinit_payload,
            &k_s,
            &q_c,
            &q_s,
            &k,
        )?;
        if cfg!(debug_assertions) {
            debug!(
                "concatenated = {:02x?}, length = {}",
                hash_data,
                hash_data.len()
            );
        }

        let signed_exchange_hash =
            hash_and_sign(self.server_config.host_key.ec_pair(), &hash_data, hash_type)
                .context("Failed to hash and sign")?;

        let signature_enc = encode_signature(&signed_exchange_hash)?;

        let payload = [
            vec![MessageType::SSH_MSG_KEX_ECDH_REPLY as u8],
            encode_string(&k_s),
            encode_string(&q_s),
            encode_string(&signature_enc),
        ]
        .concat();

        let packet = encode_packet(&payload)?;
        self.send_packet(&packet)?;

        debug!("--- END KEY EXCHANGE ---");
        Ok(())
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
    if cfg!(debug_assertions) {
        debug!("v_c = {:02x?}, len = {}", v_c, v_c.len());
        debug!("v_s = {:02x?}, len = {}", v_s, v_s.len());
        debug!("i_c = {:02x?}, len = {}", i_c, i_c.len());
        debug!("i_s = {:02x?}, len = {}", i_s, i_s.len());
        debug!("k_s = {:02x?}, len = {}", k_s, k_s.len());
        debug!("q_c = {:02x?}, len = {}", q_c, q_c.len());
        debug!("q_s = {:02x?}, len = {}", q_s, q_s.len());
        debug!(
            "k = {:02x?}, len = {}",
            encode_mpint(k),
            encode_mpint(k).len()
        );
    }

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

// RFC 5656 § 3.1
/// # Parameters:
/// - `curve_name` - name of the curve (ex: "nistp256")
/// - `key` - public key as a byte array
pub fn encode_public_key(curve_name: &str, key: &[u8]) -> Vec<u8> {
    let name = "ecdsa-sha2-".to_owned() + curve_name;
    let blob = [encode_string(curve_name.as_bytes()), encode_string(key)].concat();

    [encode_string(name.as_bytes()), blob].concat()
}

// RFC 5656 § 3.1.1
pub fn encode_signature(sig: &EcdsaSigRef) -> Result<Vec<u8>> {
    let signature_blob = [encode_mpint(sig.r()), encode_mpint(sig.s())].concat();
    if cfg!(debug_assertions) {
        debug!(
            "r = {}, length = {}",
            sig.r().to_hex_str().unwrap(),
            sig.r().num_bytes()
        );
        debug!(
            "s = {}, length = {}",
            sig.s().to_hex_str().unwrap(),
            sig.s().num_bytes()
        );
    }

    Ok([
        encode_string(b"ecdsa-sha2-nistp256"),
        encode_string(&signature_blob),
    ]
    .concat())
}
