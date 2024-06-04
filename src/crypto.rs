use anyhow::{Context, Result};
use openssl::{
    bn::{BigNum, BigNumContext},
    derive::Deriver,
    ec::{EcGroup, EcKey, EcPoint, PointConversionForm},
    ecdsa::EcdsaSig,
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

#[derive(Debug, Clone)]
pub struct HostKey {
    private_key: Vec<u8>,
    public_key: Vec<u8>,

    private_key_pem: Vec<u8>,
    public_key_pem: Vec<u8>,
}
impl<'a> HostKey {
    pub fn private_key(&'a self) -> &'a Vec<u8> {
        &self.private_key
    }
    pub fn public_key(&'a self) -> &'a Vec<u8> {
        &self.public_key
    }

    pub fn private_key_pem(&'a self) -> &'a Vec<u8> {
        &self.private_key_pem
    }
    pub fn public_key_pem(&'a self) -> &'a Vec<u8> {
        &self.public_key_pem
    }
}

pub fn generate_host_key() -> Result<HostKey> {
    let mut ctx = BigNumContext::new()?;
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
    let ec_pair = EcKey::generate(&group)?;
    let pair = HostKey {
        private_key: ec_pair.private_key().to_vec(),
        public_key: ec_pair.public_key().to_bytes(
            &group,
            PointConversionForm::UNCOMPRESSED,
            &mut ctx,
        )?,
        private_key_pem: ec_pair.private_key_to_pem()?,
        public_key_pem: ec_pair.public_key_to_pem()?,
    };

    Ok(pair)
}

// TODO: Use negotiated algorithms instead of hardcoded ones

pub struct ComputeSharedSecretResult {
    pub secret: BigNum,
    pub eph_public_key: Vec<u8>,
    pub eph_key_pair: PKey<Private>,
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
        eph_key_pair: eph_pair.clone(),
        hash_type: MessageDigest::sha256(),
    })
}

pub fn hash_and_sign(
    private_key: &PKey<Private>,
    data: &[u8],
    hash_type: MessageDigest,
) -> Result<EcdsaSig> {
    let hashed = hash(hash_type, data)?.to_vec();
    let signature = EcdsaSig::sign(&hashed, private_key.ec_key()?.as_ref())?;

    Ok(signature)
}
