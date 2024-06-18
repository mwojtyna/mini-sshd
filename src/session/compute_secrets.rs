use anyhow::Result;
use log::trace;
use openssl::{
    bn::BigNum,
    symm::{Crypter, Mode},
};

use crate::{crypto::Crypto, encoding::encode_mpint};

use super::Session;

impl<'a> Session<'a> {
    pub fn compute_secrets(&mut self, k: BigNum, h: Vec<u8>) -> Result<()> {
        let k = encode_mpint(&k);
        let k = k.as_slice();
        let h = h.as_slice();

        let algos = self.algorithms().clone();
        let hash_algo = algos.kex_algorithm.details.hash;
        let iv_len = algos
            .encryption_algorithms_client_to_server
            .details
            .cipher
            .iv_len()
            .unwrap();
        let block_size = algos
            .encryption_algorithms_client_to_server
            .details
            .block_size;

        self.session_id = h.to_vec();
        self.iv_client_server =
            Crypto::hash(&[k, h, b"A", h].concat(), hash_algo)?[..iv_len].to_vec();
        self.iv_server_client =
            Crypto::hash(&[k, h, b"B", h].concat(), hash_algo)?[..iv_len].to_vec();
        self.enc_key_client_server =
            Crypto::hash(&[k, h, b"C", h].concat(), hash_algo)?[..block_size].to_vec();
        self.enc_key_server_client =
            Crypto::hash(&[k, h, b"D", h].concat(), hash_algo)?[..block_size].to_vec();
        self.integrity_key_client_server = Crypto::hash(&[k, h, b"E", h].concat(), hash_algo)?;
        self.integrity_key_server_client = Crypto::hash(&[k, h, b"F", h].concat(), hash_algo)?;

        let mut encrypter = Crypter::new(
            algos.encryption_algorithms_server_to_client.details.cipher,
            Mode::Encrypt,
            self.enc_key_server_client(),
            Some(self.iv_server_client()),
        )?;
        encrypter.pad(false);

        let mut decrypter = Crypter::new(
            algos.encryption_algorithms_client_to_server.details.cipher,
            Mode::Decrypt,
            self.enc_key_client_server(),
            Some(self.iv_client_server()),
        )?;
        decrypter.pad(false);

        self.crypto
            .as_mut()
            .unwrap()
            .init_crypters(encrypter, decrypter);

        trace!("session_id = {:02x?}", self.session_id);
        trace!("iv_len = {}", iv_len);
        trace!("iv_client_server = {:02x?}", self.iv_client_server);
        trace!("iv_server_client = {:02x?}", self.iv_server_client);
        trace!("block_size = {}", block_size);
        trace!(
            "enc_key_client_server = {:02x?}",
            self.enc_key_client_server
        );
        trace!(
            "enc_key_server_client = {:02x?}",
            self.enc_key_server_client
        );
        trace!(
            "integrity_key_client_server = {:02x?}",
            self.integrity_key_client_server
        );
        trace!(
            "integrity_key_server_client = {:02x?}",
            self.integrity_key_server_client
        );

        Ok(())
    }
}
