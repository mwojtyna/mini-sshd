use anyhow::Result;
use log::trace;
use openssl::{
    bn::BigNum,
    symm::{Crypter, Mode},
};

use crate::{crypto::Crypto, encoding::encode_mpint, session::Secrets};

use super::Session;

impl Session {
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

        let secrets = Secrets {
            session_id: h.to_vec(),
            iv_client_server: Crypto::hash(&[k, h, b"A", h].concat(), hash_algo)?[..iv_len]
                .to_vec(),
            iv_server_client: Crypto::hash(&[k, h, b"B", h].concat(), hash_algo)?[..iv_len]
                .to_vec(),
            enc_key_client_server: Crypto::hash(&[k, h, b"C", h].concat(), hash_algo)?
                [..block_size]
                .to_vec(),
            enc_key_server_client: Crypto::hash(&[k, h, b"D", h].concat(), hash_algo)?
                [..block_size]
                .to_vec(),
            integrity_key_client_server: Crypto::hash(&[k, h, b"E", h].concat(), hash_algo)?,
            integrity_key_server_client: Crypto::hash(&[k, h, b"F", h].concat(), hash_algo)?,
        };

        let mut encrypter = Crypter::new(
            algos.encryption_algorithms_server_to_client.details.cipher,
            Mode::Encrypt,
            &secrets.enc_key_server_client,
            Some(&secrets.iv_server_client),
        )?;
        encrypter.pad(false);

        let mut decrypter = Crypter::new(
            algos.encryption_algorithms_client_to_server.details.cipher,
            Mode::Decrypt,
            &secrets.enc_key_client_server,
            Some(&secrets.iv_client_server),
        )?;
        decrypter.pad(false);

        trace!("secrets = {:02x?}", secrets);
        self.secrets = Some(secrets.into());
        self.crypto_mut()
            .lock()
            .unwrap()
            .init_crypters(encrypter, decrypter);

        Ok(())
    }
}
