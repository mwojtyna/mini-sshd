use anyhow::{Context, Result};
use log::debug;
use openssl::{
    bn::{BigNum, BigNumContext},
    derive::Deriver,
    ec::{EcGroup, EcKey, EcPoint, PointConversionForm},
    ecdsa::EcdsaSig,
    hash::{hash, MessageDigest},
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

    pub private_key_pem: Vec<u8>,
    pub public_key_pem: Vec<u8>,

    pub ec_pair: EcKey<Private>,
}

pub fn generate_host_key() -> Result<HostKey> {
    let mut ctx = BigNumContext::new()?;
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
    let ec_pair = EcKey::generate(&group)?;
    let pair = HostKey {
        public_key: ec_pair.public_key().to_bytes(
            &group,
            PointConversionForm::UNCOMPRESSED,
            &mut ctx,
        )?,
        private_key_pem: ec_pair.private_key_to_pem()?,
        public_key_pem: ec_pair.public_key_to_pem()?,
        ec_pair,
    };

    Ok(pair)
}

// TODO: Use negotiated algorithms instead of hardcoded ones

pub struct ComputeSharedSecretResult {
    pub secret: BigNum,
    pub eph_public_key: Vec<u8>,
    pub hash_type: MessageDigest,
}
pub fn compute_shared_secret(peer_key: &[u8]) -> Result<ComputeSharedSecretResult> {
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

    Ok(ComputeSharedSecretResult {
        secret,
        eph_public_key,
        hash_type: MessageDigest::sha256(),
    })
}

pub fn hash_and_sign(
    private_key: &EcKey<Private>,
    data: &[u8],
    hash_type: MessageDigest,
) -> Result<EcdsaSig> {
    // No clue why it has to be hashed twice, otherwise openssh client won't accept the signature
    let hash_first = hash(hash_type, data)?;
    let hash_final = hash(hash_type, &hash_first)?.to_vec();
    if cfg!(debug_assertions) {
        debug!("hash = {:02x?}", hash_final);
    }

    let signature = EcdsaSig::sign(&hash_final, private_key.as_ref())?;

    Ok(signature)
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
