use anyhow::{Context, Result};
use log::debug;
use openssl::{
    bn::{BigNum, BigNumContext},
    derive::Deriver,
    ec::{EcGroup, EcKey, EcPoint, PointConversionForm},
    ecdsa::EcdsaSig,
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Private, Public},
    rand::rand_bytes,
    sign::Signer,
};

use crate::{encoding::encode_u32, session::algorithm_negotiation::Algorithms};

#[derive(Debug, Clone)]
pub struct EcHostKey {
    pub public_key: Vec<u8>,
    pub ec_pair: EcKey<Private>,
}

pub struct Crypto {
    algorithms: Algorithms,
}

impl Crypto {
    pub fn new(algorithms: Algorithms) -> Self {
        Crypto { algorithms }
    }

    pub fn generate_random_array(len: usize) -> Result<Vec<u8>> {
        let mut out = vec![0; len];
        rand_bytes(&mut out).context("Failed generating random array")?;

        Ok(out)
    }

    pub fn hash(data: &[u8], hash: MessageDigest) -> Result<Vec<u8>> {
        Ok(openssl::hash::hash(hash, data)?.to_vec())
    }

    pub fn ec_generate_host_key(curve: Nid) -> Result<EcHostKey> {
        let mut ctx = BigNumContext::new()?;
        let group = EcGroup::from_curve_name(curve)?;

        let ec_pair = EcKey::generate(&group)?;
        let host_key = EcHostKey {
            public_key: ec_pair.public_key().to_bytes(
                &group,
                PointConversionForm::UNCOMPRESSED,
                &mut ctx,
            )?,
            ec_pair,
        };

        Ok(host_key)
    }

    /// # Returns
    /// `(secret, eph_public_key)`
    pub fn compute_shared_secret(&self, peer_key: &[u8]) -> Result<(BigNum, Vec<u8>)> {
        let group = EcGroup::from_curve_name(self.algorithms.kex_algorithm.details.curve)?;
        let mut ctx = BigNumContext::new()?;

        let point_from_peer_key = &EcPoint::from_bytes(&group, peer_key, &mut ctx)?;
        let peer_key: PKey<Public> =
            EcKey::from_public_key(&group, point_from_peer_key)?.try_into()?;

        let eph_pair = EcKey::generate(&group)?;
        let eph_public_key =
            eph_pair
                .public_key()
                .to_bytes(&group, PointConversionForm::UNCOMPRESSED, &mut ctx)?;

        let eph_pair = PKey::from_ec_key(eph_pair.clone())?;
        let mut deriver = Deriver::new(&eph_pair)?;
        deriver.set_peer_ex(&peer_key, true)?;

        let secret_bytes = deriver.derive_to_vec()?;
        let secret = BigNum::from_slice(&secret_bytes)?;

        Ok((secret, eph_public_key))
    }

    /// # Returns
    /// `(hash, signature)`
    pub fn ec_hash_and_sign(
        &self,
        private_key: &EcKey<Private>,
        data: &[u8],
    ) -> Result<(Vec<u8>, EcdsaSig)> {
        let hashed_data = Self::hash(data, self.algorithms.kex_algorithm.details.hash)?;
        if cfg!(debug_assertions) {
            debug!("hash = {:02x?}", hashed_data);
        }

        let ecdsa_hash = Self::hash(&hashed_data, self.algorithms.kex_algorithm.details.hash)?;
        let signed = EcdsaSig::sign(&ecdsa_hash, private_key.as_ref())?;

        Ok((hashed_data, signed))
    }

    // RFC 4253 § 6.4
    pub fn compute_mac(&self, key: &[u8], sequence_num: u32, packet: &[u8]) -> Result<Vec<u8>> {
        let pkey = PKey::hmac(key)?;
        let mut signer = Signer::new(
            self.algorithms.mac_algorithms_server_to_client.details.hash,
            &pkey,
        )?;
        signer.update(&encode_u32(sequence_num))?;
        signer.update(packet)?;

        let mac = signer.sign_to_vec()?;
        Ok(mac)
    }
}
