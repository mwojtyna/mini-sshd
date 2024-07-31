use core::mem::size_of;

use anyhow::{bail, Context, Result};
use log::{debug, trace};

use crate::{
    crypto::Crypto,
    decoding::{decode_ec_public_key, decode_ec_signature, PayloadReader},
    def_enum,
    encoding::{encode_string, PacketBuilder, STRING_LENGTH_SIZE},
    hex_dump,
    types::{HostKeyAlgorithm, MessageType},
    AuthorizedKey,
};

use super::Session;

const BANNER: &str = r"######################################
#                                    #
#    mini-sshd by Mateusz Wojtyna    #
#                                    # 
######################################
";

macro_rules! reject_with_err {
    ($session:expr, $partial_success:expr, $error_msg:expr) => {
        log::error!("{}", $error_msg);
        reject($session, $partial_success)?;
        return Ok(());
    };
}

def_enum!(pub AuthenticationMethod => &'static str {
    PUBLIC_KEY => "publickey",
    // PASSWORD => "password",
    // HOSTBASED => "hostbased",
    NONE => "none",
});

impl Session {
    // RFC 4252
    pub fn userauth(&mut self, reader: &mut PayloadReader) -> Result<()> {
        debug!("--- BEGIN USERAUTH REQUEST ---");

        let user_name = reader.next_string_utf8()?;
        trace!("username = {}", user_name);

        if user_name == "root" {
            bail!("Connecting to root user not allowed");
        }

        let service_name = reader.next_string_utf8()?;

        let method_name = reader.next_string_utf8()?;
        debug!("method_name = {}", method_name);

        match method_name.as_str() {
            AuthenticationMethod::NONE => {
                reject(self, false)?;
            }
            AuthenticationMethod::PUBLIC_KEY => {
                self.public_key_auth(reader, &user_name, &service_name)?;
            }

            _ => {
                reject(self, false)?;
            }
        }

        self.user_name = Some(user_name.into());

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
        let authenticate = reader.next_bool().context("Invalid packet")?;

        let public_key_alg_name = reader.next_string_utf8()?;
        debug!("public_key_algorithm_name = {}", public_key_alg_name);

        if !HostKeyAlgorithm::VARIANTS.contains(&public_key_alg_name.as_str()) {
            reject_with_err!(
                self,
                false,
                format!("Unsupported public key algorithm '{}'", public_key_alg_name).as_str()
            );
        }

        let public_key_blob = reader.next_string()?;
        hex_dump!(public_key_blob);

        if !authenticate {
            let pk_ok = PacketBuilder::new(MessageType::SSH_MSG_USERAUTH_PK_OK, self)
                .write_string(public_key_alg_name.as_bytes())
                .write_string(&public_key_blob)
                .build()?;
            self.send_packet(&pk_ok)?;
        } else {
            let client_public_key_algo = self
                .server_config
                .algorithms
                .client_host_key_algorithms
                .get(&public_key_alg_name.as_str())
                .unwrap();

            let signature = reader.next_string()?;
            trace!("signature = {:02x?}", signature);

            let signature = decode_ec_signature(&signature)?;
            let (public_key_bytes, public_key) =
                decode_ec_public_key(&public_key_blob, client_public_key_algo.curve)?;
            trace!("public_key = {:02x?}", public_key_bytes);

            if !self.server_config.authorized_keys.contains(&AuthorizedKey {
                public_key: public_key_bytes,
                user_name: user_name.to_owned(),
            }) {
                reject_with_err!(
                    self,
                    false,
                    "Public key not in 'authorized_keys' file or username doesn't match"
                );
            }

            let digest_data = self.concat_digest_data(
                user_name,
                service_name,
                &public_key_alg_name,
                &public_key_blob,
            );
            let digest = Crypto::hash(&digest_data, client_public_key_algo.hash)?;

            let valid = signature.verify(&digest, &public_key)?;
            if !valid {
                reject_with_err!(self, false, "Signature not valid");
            }

            let banner_packet = PacketBuilder::new(MessageType::SSH_MSG_USERAUTH_BANNER, self)
                .write_string(BANNER.as_bytes())
                .write_string(b"en")
                .build()?;
            self.send_packet(&banner_packet)?;

            let packet = PacketBuilder::new(MessageType::SSH_MSG_USERAUTH_SUCCESS, self).build()?;
            self.send_packet(&packet)?;
        }

        Ok(())
    }

    fn concat_digest_data(
        &self,
        user_name: &str,
        service_name: &str,
        public_key_alg_name: &str,
        public_key_blob: &[u8],
    ) -> Vec<u8> {
        let mut digest_data = Vec::with_capacity(
            (STRING_LENGTH_SIZE + self.secrets().session_id.len())
                + size_of::<u8>()
                + (STRING_LENGTH_SIZE + user_name.len())
                + (STRING_LENGTH_SIZE + service_name.len())
                + (STRING_LENGTH_SIZE + AuthenticationMethod::PUBLIC_KEY.len())
                + size_of::<u8>()
                + (STRING_LENGTH_SIZE + public_key_alg_name.len())
                + (STRING_LENGTH_SIZE + public_key_blob.len()),
        );
        digest_data.extend(encode_string(&self.secrets().session_id));
        digest_data.push(MessageType::SSH_MSG_USERAUTH_REQUEST as u8);
        digest_data.extend(encode_string(user_name.as_bytes()));
        digest_data.extend(encode_string(service_name.as_bytes()));
        digest_data.extend(encode_string(AuthenticationMethod::PUBLIC_KEY.as_bytes()));
        digest_data.push(true as u8);
        digest_data.extend(encode_string(public_key_alg_name.as_bytes()));
        digest_data.extend(encode_string(public_key_blob));
        digest_data
    }
}

// RFC 4252 § 5.1
fn reject(session: &mut Session, partial_success: bool) -> Result<()> {
    let auths: Vec<&str> = AuthenticationMethod::VARIANTS
        .iter()
        .filter(|m| **m != AuthenticationMethod::NONE)
        .copied()
        .collect();

    let packet = PacketBuilder::new(MessageType::SSH_MSG_USERAUTH_FAILURE, session)
        .write_name_list(&auths)
        .write_bool(partial_success)
        .build()?;
    session.send_packet(&packet)?;

    Ok(())
}
