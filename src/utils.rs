use anyhow::{anyhow, Result};
use ring::rand::{SecureRandom, SystemRandom};

pub fn packet_too_short<T>(var_name: &str) -> Result<T> {
    Err(anyhow!(
        "Packet too short - '{}' could not be read",
        var_name
    ))
}

pub fn random_array(len: usize) -> Result<Vec<u8>> {
    let mut out = vec![0u8; len];
    let sr = SystemRandom::new();

    if sr.fill(out.as_mut_slice()).is_err() {
        Err(anyhow!("Failed generating random array"))
    } else {
        Ok(out)
    }
}
