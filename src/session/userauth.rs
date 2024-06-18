use anyhow::{anyhow, Result};
use log::{debug, error, trace};
use openssl::{hash::MessageDigest, nid::Nid};

use crate::{
    crypto::Crypto,
    decoding::{decode_ec_signature, decode_openssh_ec_private_key, PayloadReader},
    encoding::{encode_string, PacketBuilder},
    types::{AuthenticationMethod, HostKeyAlgorithm, HostKeyAlgorithmDetails, MessageType},
};

use super::{algorithm_negotiation::Algorithm, Session};

const PRIVATE_KEY: &str = include_str!("/home/mati/.ssh/localhost_id_ecdsa");

#[rustfmt::skip]
const BANNER: &str = 
r"######################################
#                                    #
#    mini-sshd by Mateusz Wojtyna    #
#                                    # 
######################################
";

impl<'a> Session<'a> {
    pub(super) fn userauth(&mut self, reader: &mut PayloadReader) -> Result<()> {
        debug!("--- BEGIN USERAUTH REQUEST ---");

        let user_name = reader.next_string_utf8()?;
        trace!("username = {}", user_name);

        let service_name = reader.next_string_utf8()?;

        let method_name = reader.next_string_utf8()?;
        debug!("method_name = {}", method_name);

        match method_name.as_str() {
            AuthenticationMethod::NONE => {
                self.reject(false)?;
            }
            AuthenticationMethod::PUBLIC_KEY => {
                self.public_key_auth(reader, &user_name, &service_name)?;
            }

            _ => {
                self.reject(false)?;
            }
        }

        debug!("--- END USERAUTH REQUEST ---");
        Ok(())
    }

    // RFC 4252 § 7
    fn public_key_auth(
        &mut self,
        reader: &mut PayloadReader,
        user_name: &str,
        service_name: &str,
    ) -> Result<()> {
        // TODO: Don't hardcode this
        let client_public_key_algo: Algorithm<HostKeyAlgorithmDetails> = Algorithm {
            name: HostKeyAlgorithm::ECDSA_SHA2_NISTP256.to_owned(),
            details: HostKeyAlgorithmDetails {
                hash: MessageDigest::sha256(),
                curve: Nid::X9_62_PRIME256V1,
            },
        };

        let authenticate = reader.next_bool().ok_or(anyhow!("Invalid packet"))?;

        let public_key_alg_name = reader.next_string_utf8()?;
        debug!("public_key_algorithm_name = {}", public_key_alg_name);

        let public_key_blob = reader.next_string()?;
        trace!("public_key_blob = {:02x?}", public_key_blob);

        if !authenticate {
            let pk_ok = PacketBuilder::new(MessageType::SSH_MSG_USERAUTH_PK_OK, self)
                .write_string(public_key_alg_name.as_bytes())
                .write_string(&public_key_blob)
                .build()?;
            self.send_packet(&pk_ok)?;
        } else {
            let signature = reader.next_string()?;
            trace!("signature = {:02x?}", signature);

            let signature = decode_ec_signature(&signature)?;
            let private_key = decode_openssh_ec_private_key(PRIVATE_KEY, &client_public_key_algo)?;
            trace!("private_key = {:02x?}", private_key.private_key());

            let mut digest_data = Vec::with_capacity(
                (4 + self.session_id.len())
                    + 1
                    + (4 + user_name.len())
                    + (4 + service_name.len())
                    + (4 + AuthenticationMethod::PUBLIC_KEY.len())
                    + 1
                    + (4 + public_key_alg_name.len())
                    + (4 + public_key_blob.len()),
            );
            digest_data.extend(encode_string(&self.session_id));
            digest_data.push(MessageType::SSH_MSG_USERAUTH_REQUEST as u8);
            digest_data.extend(encode_string(user_name.as_bytes()));
            digest_data.extend(encode_string(service_name.as_bytes()));
            digest_data.extend(encode_string(AuthenticationMethod::PUBLIC_KEY.as_bytes()));
            digest_data.push(true as u8);
            digest_data.extend(encode_string(public_key_alg_name.as_bytes()));
            digest_data.extend(encode_string(&public_key_blob));

            let digest = Crypto::hash(&digest_data, client_public_key_algo.details.hash)?;
            let valid = signature.verify(&digest, &private_key)?;

            if !valid {
                error!("Signature not valid");
                self.reject(false)?;
            } else {
                let banner_packet = PacketBuilder::new(MessageType::SSH_MSG_USERAUTH_BANNER, self)
                    .write_string(BANNER.as_bytes())
                    .write_string(b"en")
                    .build()?;
                self.send_packet(&banner_packet)?;

                let packet =
                    PacketBuilder::new(MessageType::SSH_MSG_USERAUTH_SUCCESS, self).build()?;
                self.send_packet(&packet)?;
            }
        }

        Ok(())
    }

    // RFC 4252 § 5.1
    fn reject(&mut self, partial_success: bool) -> Result<()> {
        let auths = AuthenticationMethod::VARIANTS
            .iter()
            .filter(|m| **m != AuthenticationMethod::NONE)
            .copied()
            .collect::<Vec<&str>>();

        let packet = PacketBuilder::new(MessageType::SSH_MSG_USERAUTH_FAILURE, self)
            .write_name_list(&auths)
            .write_bool(partial_success)
            .build()?;
        self.send_packet(&packet)?;

        Ok(())
    }
}
