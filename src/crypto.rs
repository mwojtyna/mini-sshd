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

use crate::encoding::encode_u32;

pub fn generate_random_array(len: usize) -> Result<Vec<u8>> {
    let mut out = vec![0; len];
    rand_bytes(&mut out).context("Failed generating random array")?;

    Ok(out)
}

#[derive(Debug, Clone)]
pub struct HostKey {
    pub public_key: Vec<u8>,
    pub ec_pair: EcKey<Private>,
}

pub fn generate_host_key() -> Result<HostKey> {
    let mut ctx = BigNumContext::new()?;
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;

    let ec_pair = EcKey::generate(&group)?;
    let host_key = HostKey {
        public_key: ec_pair.public_key().to_bytes(
            &group,
            PointConversionForm::UNCOMPRESSED,
            &mut ctx,
        )?,
        ec_pair,
    };

    Ok(host_key)
}

// TODO: Use negotiated algorithms instead of hardcoded ones

/// # Returns
/// `(secret, eph_public_key)`
pub fn compute_shared_secret(peer_key: &[u8]) -> Result<(BigNum, Vec<u8>)> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
    let mut ctx = BigNumContext::new()?;

    let point_from_peer_key = &EcPoint::from_bytes(&group, peer_key, &mut ctx)?;
    let peer_key: PKey<Public> = EcKey::from_public_key(&group, point_from_peer_key)?.try_into()?;

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

pub fn hash(data: &[u8]) -> Result<Vec<u8>> {
    Ok(openssl::hash::hash(MessageDigest::sha256(), data)?.to_vec())
}

/// # Returns
/// `(hash, signature)`
pub fn hash_and_sign(private_key: &EcKey<Private>, data: &[u8]) -> Result<(Vec<u8>, EcdsaSig)> {
    let hashed_data = hash(data)?;
    if cfg!(debug_assertions) {
        debug!("hash = {:02x?}", hashed_data);
    }

    let ecdsa_hash = hash(&hashed_data)?;
    let signed = EcdsaSig::sign(&ecdsa_hash, private_key.as_ref())?;

    Ok((hashed_data, signed))
}

// RFC 4253 § 6.4
pub fn compute_mac(shared_secret: &[u8], sequence_num: u32, packet: &[u8]) -> Result<Vec<u8>> {
    let pkey = PKey::hmac(shared_secret)?;
    let mut signer = Signer::new(MessageDigest::sha256(), &pkey)?;
    signer.update(&encode_u32(sequence_num))?;
    signer.update(packet)?;

    let mac = signer.sign_to_vec()?;
    Ok(mac)
}
