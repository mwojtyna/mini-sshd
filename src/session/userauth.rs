use anyhow::{anyhow, Result};
use log::{debug, warn};

use crate::{
    decoding::PayloadReader,
    encoding::PacketBuilder,
    types::{AuthenticationMethod, HostKeyAlgorithm, MessageType},
};

use super::Session;

impl<'a> Session<'a> {
    pub(super) fn userauth(&mut self, reader: &mut PayloadReader) -> Result<()> {
        debug!("--- BEGIN USERAUTH REQUEST ---");

        let username = String::from_utf8(reader.next_string()?)?;
        debug!("username = {}", username);

        let service_name = String::from_utf8(reader.next_string()?)?;
        debug!("service_name = {}", service_name);

        let method_name = String::from_utf8(reader.next_string()?)?;
        debug!("method_name = {}", method_name);

        // let banner_packet = PacketBuilder::new(MessageType::SSH_MSG_USERAUTH_BANNER, self)
        //     .write_string(b"USING MINI-SSHD\n")
        //     .write_string(b"en-US")
        //     .build()?;
        // self.send_packet(&banner_packet)?;

        match method_name.as_str() {
            AuthenticationMethod::NONE => {
                self.reject(false)?;
            }
            AuthenticationMethod::PUBLIC_KEY => {
                let _false = reader.next_bool().ok_or(anyhow!("Invalid packet"))?;

                let pkey_alg_name = String::from_utf8(reader.next_string()?)?;
                debug!("public_key_algorithm_name = {}", pkey_alg_name);

                if !HostKeyAlgorithm::VARIANTS.contains(&pkey_alg_name.as_str()) {
                    warn!("Public key algorithm {} is not supported", pkey_alg_name);
                    self.reject(false)?;
                }

                let pkey_blob = reader.next_string()?;
                if cfg!(debug_assertions) {
                    debug!("public_key_blob = {:02x?}", pkey_blob);
                }
            }

            _ => {
                self.reject(false)?;
            }
        }

        debug!("--- END USERAUTH REQUEST ---");
        Ok(())
    }

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
