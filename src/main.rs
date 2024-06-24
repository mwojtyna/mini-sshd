use std::{
    collections::{HashMap, HashSet},
    fs::{read_to_string, File},
    net::TcpListener,
    path::Path,
    sync::OnceLock,
    thread,
};

use anyhow::{Context, Result};
use crypto::{Crypto, EcHostKey};
use decoding::decode_ec_public_key;
use dirs::home_dir;
use indexmap::indexmap;
use log::{debug, error, info, trace, warn};
use openssl::{base64, hash::MessageDigest, nid::Nid, symm::Cipher};
use session::{algorithm_negotiation::ServerAlgorithms, Session};
use types::{
    CompressionAlgorithm, EncryptionAlgorithm, EncryptionAlgorithmDetails, HmacAlgorithm,
    HmacAlgorithmDetails, HostKeyAlgorithm, HostKeyAlgorithmDetails, KexAlgorithm,
    KexAlgorithmDetails,
};

mod channel;
mod crypto;
mod decoding;
mod encoding;
mod macros;
mod session;
mod types;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const PORT: usize = 6969;

static SERVER_CONFIG: OnceLock<ServerConfig> = OnceLock::new();

pub struct ServerConfig {
    ident_string: String,
    algorithms: ServerAlgorithms,
    host_key: HashMap<&'static str, EcHostKey>,
    authorized_keys: HashSet<Vec<u8>>,
}

fn main() -> Result<()> {
    env_logger::builder().format_target(false).init();

    let algorithms = ServerAlgorithms {
        // RFC 9142 § 4
        kex_algorithms: indexmap! {
            KexAlgorithm::ECDH_SHA2_NISTP256 => KexAlgorithmDetails {
                hash: MessageDigest::sha256(),
                curve: Nid::X9_62_PRIME256V1
            },
            KexAlgorithm::ECDH_SHA2_NISTP384 => KexAlgorithmDetails {
                hash: MessageDigest::sha384(),
                curve: Nid::SECP384R1
            },
            KexAlgorithm::ECDH_SHA2_NISTP521 => KexAlgorithmDetails {
                hash: MessageDigest::sha512(),
                curve: Nid::SECP521R1
            },
        },

        // RFC 5656 § 10.1
        server_host_key_algorithms: indexmap! {
            HostKeyAlgorithm::ECDSA_SHA2_NISTP256 => HostKeyAlgorithmDetails {
                hash: MessageDigest::sha256(),
                curve: Nid::X9_62_PRIME256V1
            },
            HostKeyAlgorithm::ECDSA_SHA2_NISTP384 => HostKeyAlgorithmDetails {
                hash: MessageDigest::sha384(),
                curve: Nid::SECP384R1
            },
            HostKeyAlgorithm::ECDSA_SHA2_NISTP521 => HostKeyAlgorithmDetails {
                hash: MessageDigest::sha512(),
                curve: Nid::SECP521R1
            },
        },

        client_host_key_algorithms: indexmap! {
            HostKeyAlgorithm::ECDSA_SHA2_NISTP256 => HostKeyAlgorithmDetails {
                hash: MessageDigest::sha256(),
                curve: Nid::X9_62_PRIME256V1
            },
            HostKeyAlgorithm::ECDSA_SHA2_NISTP384 => HostKeyAlgorithmDetails {
                hash: MessageDigest::sha384(),
                curve: Nid::SECP384R1
            },
            HostKeyAlgorithm::ECDSA_SHA2_NISTP521 => HostKeyAlgorithmDetails {
                hash: MessageDigest::sha512(),
                curve: Nid::SECP521R1
            },
        },

        // RFC 4344 § 4
        encryption_algorithms_server_to_client: indexmap! {
            EncryptionAlgorithm::AES128_CTR => EncryptionAlgorithmDetails {
                cipher: Cipher::aes_128_ctr(),
                block_size: 16,
            },
        },
        encryption_algorithms_client_to_server: indexmap! {
            EncryptionAlgorithm::AES128_CTR => EncryptionAlgorithmDetails {
                cipher: Cipher::aes_128_ctr(),
                block_size: 16,
            },
        },

        // RFC 6668 § 2
        mac_algorithms_server_to_client: indexmap! {
            HmacAlgorithm::HMAC_SHA2_256 => HmacAlgorithmDetails {
                hash: MessageDigest::sha256(),
            }
        },
        mac_algorithms_client_to_server: indexmap! {
            HmacAlgorithm::HMAC_SHA2_256 => HmacAlgorithmDetails {
                hash: MessageDigest::sha256(),
            }
        },

        compression_algorithms_client_to_server: indexmap! {
            CompressionAlgorithm::NONE => None,
        },
        compression_algorithms_server_to_client: indexmap! {
            CompressionAlgorithm::NONE => None,
        },

        languages_client_to_server: vec![""],
        languages_server_to_client: vec![""],
    };

    let authorized_keys =
        read_authorized_keys(&algorithms).context("Failed to read 'authorized_keys' file")?;
    trace!("authorized_keys = {:02x?}", authorized_keys);

    let _ = SERVER_CONFIG.set(ServerConfig {
        ident_string: format!("SSH-2.0-minisshd_{}", VERSION),
        algorithms: algorithms.clone(),
        host_key: hashmap! {
            HostKeyAlgorithm::ECDSA_SHA2_NISTP256 => Crypto::ec_generate_host_key(algorithms.server_host_key_algorithms.get(HostKeyAlgorithm::ECDSA_SHA2_NISTP256).unwrap().curve)?,
            HostKeyAlgorithm::ECDSA_SHA2_NISTP384 => Crypto::ec_generate_host_key(algorithms.server_host_key_algorithms.get(HostKeyAlgorithm::ECDSA_SHA2_NISTP384).unwrap().curve)?,
            HostKeyAlgorithm::ECDSA_SHA2_NISTP521 => Crypto::ec_generate_host_key(algorithms.server_host_key_algorithms.get(HostKeyAlgorithm::ECDSA_SHA2_NISTP521).unwrap().curve)?
        },
        authorized_keys,
    });

    if let Err(err) = connect() {
        error!("{:?}", err);
    }

    Ok(())
}

fn read_authorized_keys(supported_algos: &ServerAlgorithms) -> Result<HashSet<Vec<u8>>> {
    trace!("--- BEGIN AUTHORIZED_KEYS READ ---");

    // TODO: Config file
    const AUTHORIZED_KEYS_PATH: &str = ".ssh/authorized_keys";

    let home = home_dir().context("Failed to get home directory")?;
    let path = home.join(Path::new(AUTHORIZED_KEYS_PATH));

    if !path.exists() {
        info!("'authorized_keys' file does not exist, creating...");
        File::create_new(&path)?;
    }

    let contents = read_to_string(path)?;
    let split: Vec<&str> = contents.trim().split('\n').collect();
    let mut public_keys = HashSet::new();

    for (n, line) in split.iter().enumerate() {
        let mut parts = line.split(' ');
        let algo_name = parts.next().context("Failed reading algorithm name")?;
        trace!("algo_name_{}: {}", n, algo_name);

        let algo = supported_algos.client_host_key_algorithms.get(algo_name);
        if let Some(algo) = algo {
            let public_key_b64 = parts.next().context("Failed reading public key")?;
            trace!("public_key_b64_{}: {}", n, public_key_b64);

            let public_key_encoded = base64::decode_block(public_key_b64)?;
            hex_dump!(public_key_encoded);

            let (public_key_bytes, _) = decode_ec_public_key(&public_key_encoded, algo.curve)?;
            public_keys.insert(public_key_bytes);

            let host = parts.next().context("Failed reading host")?;
            trace!("host_{}: {}", n, host);
        } else {
            warn!(
                "Unsupported public key algorithm '{}' in 'authorized_keys' file, skipping...",
                algo_name
            );
        }
    }

    trace!("--- END AUTHORIZED_KEYS READ ---");
    Ok(public_keys)
}

fn connect() -> Result<()> {
    let listener = TcpListener::bind(format!("127.0.0.1:{}", PORT))?;

    for client in listener.incoming() {
        let stream = client.context("Client is invalid")?;
        let client_addr = stream.peer_addr().unwrap();

        let handle = thread::spawn::<_, Result<()>>(|| {
            let mut session = Session::new(stream, SERVER_CONFIG.get().unwrap());
            session.start()?;
            Ok(())
        });

        // TODO: Join on seperate thread
        match handle.join() {
            Ok(val) => match val {
                Ok(()) => debug!("Session for address {} finished successfully", client_addr),
                Err(err) => error!(
                    "Session for address {} finished with error: {:?}",
                    client_addr, err
                ),
            },
            Err(_) => error!("Session for address {} panicked", client_addr),
        }
    }

    Ok(())
}
