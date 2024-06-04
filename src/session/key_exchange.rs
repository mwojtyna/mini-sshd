use anyhow::{Context, Result};
use log::debug;
use openssl::{bn::BigNum, ecdsa::EcdsaSigRef};

use crate::{
    crypto::{compute_shared_secret, hash_and_sign, ComputeSharedSecretResult},
    decoding::{decode_string, DecodedPacket},
    encoding::{encode_mpint, encode_packet, encode_public_key, encode_string},
    types::MessageType,
    Session,
};

impl Session {
    // RFC 5656 § 4
    pub(super) fn key_exchange(&mut self, packet: DecodedPacket) -> Result<()> {
        debug!("--- BEGIN KEY EXCHANGE ---");

        // Client's public key
        let q_c = decode_string(&mut packet.payload.into_iter())?;
        if cfg!(debug_assertions) {
            debug!(
                "q_c = {:?}, length = {}",
                String::from_utf8_lossy(&q_c),
                q_c.len()
            );
        }

        // Server's public host key
        let k_s = encode_public_key(
            "ssh-ed25519",
            &self.server_config.host_key.raw_public_key()?,
        );
        if cfg!(debug_assertions) {
            debug!(
                "k_s = {:?}, length = {}",
                String::from_utf8_lossy(&k_s),
                k_s.len()
            );
        }

        let ComputeSharedSecretResult {
            secret: k,
            eph_public_key: q_s,
            eph_key_pair,
            hash_type,
        } = compute_shared_secret(&q_c).context("Failed computing shared secret")?;

        if cfg!(debug_assertions) {
            debug!(
                "q_s = {:?}, length = {}",
                String::from_utf8_lossy(&q_s),
                q_s.len()
            );
        }
        if cfg!(debug_assertions) {
            debug!("shared_secret = {:?}, length = {}", &k, k.num_bytes());
        }

        let hash_data = concat_hash_data(
            self.client_ident.as_bytes(),
            self.server_config.ident_string.as_bytes(),
            &self.client_kexinit_payload,
            &self.server_kexinit_payload,
            &k_s,
            &q_c,
            &q_s,
            &k,
        );
        let signed_exchange_hash = hash_and_sign(&eph_key_pair, &hash_data, hash_type)
            .context("Failed to hash and sign")?;

        let signature_enc = encode_signature(&signed_exchange_hash);
        if cfg!(debug_assertions) {
            debug!(
                "signature = {:?}, length = {}",
                &signature_enc,
                &signature_enc.len()
            );
        }

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
) -> Vec<u8> {
    let v_c = encode_string(v_c);
    let v_s = encode_string(v_s);
    let i_c = encode_string(i_c);
    let i_s = encode_string(i_s);
    let k_s = encode_string(k_s);
    let q_c = encode_string(q_c);
    let q_s = encode_string(q_s);
    let k = encode_mpint(k);

    [v_c, v_s, i_c, i_s, k_s, q_c, q_s, k].concat()
}

// RFC 5656 § 3.1.1
fn encode_signature(sig: &EcdsaSigRef) -> Vec<u8> {
    let signature_blob = [encode_mpint(sig.r()), encode_mpint(sig.s())].concat();
    if cfg!(debug_assertions) {
        debug!(
            "r = {:?}, length = {}",
            sig.r().to_vec(),
            sig.r().num_bytes()
        );
        debug!(
            "s = {:?}, length = {}",
            sig.s().to_vec(),
            sig.s().num_bytes()
        );
    }

    [
        encode_string(b"ecdsa-sha2-nistp256"),
        encode_string(&signature_blob),
    ]
    .concat()
}
