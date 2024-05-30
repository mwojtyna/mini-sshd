use anyhow::{Context, Result};
use openssl::rand::rand_bytes;

pub fn random_array(len: usize) -> Result<Vec<u8>> {
    let mut out = vec![0; len];
    rand_bytes(&mut out).with_context(|| "Failed generating random array")?;

    Ok(out)
}
