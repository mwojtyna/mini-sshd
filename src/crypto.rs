use anyhow::{Context, Result};
use openssl::{
    bn::BigNumContext,
    derive::Deriver,
    ec::{EcGroup, EcKey, EcPoint, PointConversionForm},
    hash::{hash, MessageDigest},
    nid::Nid,
    pkey::{PKey, Private, Public},
    rand::rand_bytes,
};

pub fn generate_random_array(len: usize) -> Result<Vec<u8>> {
    let mut out = vec![0; len];
    rand_bytes(&mut out).context("Failed generating random array")?;

    Ok(out)
}

// TODO: Use negotiated algorithms instead of hardcoded ones

pub struct SharedSecret {
    pub secret: Vec<u8>,
    pub eph_public_key: Vec<u8>,
}
pub fn compute_shared_secret(peer_key: &[u8]) -> Result<SharedSecret> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
    let mut ctx = BigNumContext::new()?;

    let point_from_peer_key = &EcPoint::from_bytes(&group, peer_key, &mut ctx)?;
    let peer_key: PKey<Public> = EcKey::from_public_key(&group, point_from_peer_key)?.try_into()?;

    let eph_pair = EcKey::generate(&group)?;
    let eph_public_key =
        eph_pair
            .public_key()
            .to_bytes(&group, PointConversionForm::UNCOMPRESSED, &mut ctx)?;

    let eph_pair = PKey::from_ec_key(eph_pair)?;
    let mut deriver = Deriver::new(&eph_pair)?;
    deriver.set_peer_ex(&peer_key, true)?;

    let secret = deriver.derive_to_vec()?;
    let hashed_secret = hash(MessageDigest::sha256(), &secret)?.to_vec();

    Ok(SharedSecret {
        secret: hashed_secret,
        eph_public_key,
    })
}

pub type HostKey = PKey<Private>;
pub fn generate_host_key() -> Result<HostKey> {
    let key = PKey::generate_ed25519()?;
    Ok(key)
}
