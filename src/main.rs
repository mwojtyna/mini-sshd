#![warn(clippy::use_self)]
#![warn(clippy::missing_const_for_fn)]
#![warn(clippy::redundant_clone)]
#![warn(clippy::cloned_instead_of_copied)]
#![warn(clippy::needless_collect)]
#![warn(clippy::nursery)]
#![allow(clippy::significant_drop_tightening)]
#![allow(clippy::derive_partial_eq_without_eq)]

use std::{
    collections::{HashMap, HashSet},
    fs::{self, File, Permissions},
    io::{Read, Write},
    net::TcpListener,
    os::unix::fs::PermissionsExt,
    path::Path,
    sync::OnceLock,
};

use anyhow::{Context, Result};
use clap::Parser;
use crypto::{Crypto, EcHostKey};
use decoding::decode_ec_public_key;
use indexmap::indexmap;
use log::{debug, error, info, trace, warn, LevelFilter};
use openssl::{base64, ec::EcKey, hash::MessageDigest, nid::Nid, symm::Cipher};
use session::{algorithm_negotiation::ServerAlgorithms, Session};
use tokio::task::JoinHandle;
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
static SERVER_CONFIG: OnceLock<ServerConfig> = OnceLock::new();

#[derive(PartialEq, Eq, Hash, Debug)]
pub struct AuthorizedKey {
    pub public_key: Vec<u8>,
    pub user_name: String,
}

pub struct ServerConfig {
    ident_string: String,
    algorithms: ServerAlgorithms,
    host_keys: HashMap<String, EcHostKey>,
    authorized_keys: HashSet<AuthorizedKey>,
}

#[derive(Parser, Debug)]
#[command(version)]
struct Args {
    #[arg(short, long, default_value_t = 22)]
    port: usize,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::builder()
        .format_target(false)
        .filter_level(LevelFilter::Info)
        .init();

    let args = Args::parse();
    let algorithms = get_server_algorithms();
    let host_keys = read_host_keys(&algorithms).context("Failed to read host keys from disk")?;

    let authorized_keys =
        read_authorized_keys(&algorithms).context("Failed to read 'authorized_keys' file")?;
    trace!("authorized_keys = {:02x?}", authorized_keys);

    let _ = SERVER_CONFIG.set(ServerConfig {
        ident_string: format!("SSH-2.0-minisshd_{}", VERSION),
        algorithms,
        host_keys,
        authorized_keys,
    });

    info!("Opened server on port {}", args.port);

    if let Err(err) = connect(args.port).await {
        error!("{:?}", err);
    }

    Ok(())
}

async fn connect(port: usize) -> Result<()> {
    let listener = TcpListener::bind(format!("0.0.0.0:{}", port))
        .context(format!("Failed to create a tcp listener on port {}", port))?;

    for client in listener.incoming() {
        let stream = client.context("Client is invalid")?;
        let client_addr = stream.peer_addr().unwrap();

        let handle: JoinHandle<Result<()>> = tokio::task::spawn(async {
            let mut session = Session::new(stream, SERVER_CONFIG.get().unwrap());
            session.start()?;
            Ok(())
        });
        tokio::task::spawn(async move {
            match handle.await {
                Ok(val) => match val {
                    Ok(()) => debug!("Session for address {} finished successfully", client_addr),
                    Err(err) => error!(
                        "Session for address {} finished with error: {:?}",
                        client_addr, err
                    ),
                },
                Err(_) => error!("Session for address {} panicked", client_addr),
            }
        });
    }

    Ok(())
}

fn read_authorized_keys(supported_algos: &ServerAlgorithms) -> Result<HashSet<AuthorizedKey>> {
    trace!("--- BEGIN AUTHORIZED_KEYS READ ---");

    const AUTHORIZED_KEYS_PATH: &str = ".ssh/authorized_keys";

    let home = dirs::home_dir().context("Failed to get home directory")?;
    let path = home.join(Path::new(AUTHORIZED_KEYS_PATH));

    if !path.exists() {
        info!("'authorized_keys' file does not exist, creating...");
        File::create_new(&path)?;
    }

    let contents = fs::read_to_string(path)?;
    let split: Vec<&str> = contents.trim().split('\n').collect();
    let mut authorized_keys = HashSet::new();

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

            let host = parts.next().context("Failed reading host")?;
            trace!("host_{}: {}", n, host);

            let user_name = host.split('@').next().context("Failed reading user name")?;
            trace!("user_name_{}: {}", n, user_name);

            authorized_keys.insert(AuthorizedKey {
                public_key: public_key_bytes,
                user_name: user_name.to_owned(),
            });
        } else {
            warn!(
                "Unsupported public key algorithm '{}' in 'authorized_keys' file, skipping...",
                algo_name
            );
        }
    }

    trace!("--- END AUTHORIZED_KEYS READ ---");
    Ok(authorized_keys)
}

fn read_host_keys(algos: &ServerAlgorithms) -> Result<HashMap<String, EcHostKey>> {
    const HOST_KEYS_FOLDER: &str = "mini-sshd";

    let data_dir = dirs::data_dir().context("Failed to get data directory")?;
    let dir = data_dir.join(HOST_KEYS_FOLDER);

    if !Path::exists(&dir) {
        fs::create_dir(&dir).context("Failed to create data directory")?;
    }

    let mut keys = HashMap::new();
    for algo_name in HostKeyAlgorithm::VARIANTS {
        let curve = algos
            .server_host_key_algorithms
            .get(algo_name)
            .unwrap()
            .curve;

        let private_key_path = dir.join(format!("ssh_host_{}_key", algo_name));
        let public_key_path = dir.join(format!("ssh_host_{}_key.pub", algo_name));

        let private_key_exists = Path::exists(&private_key_path);
        let public_key_exists = Path::exists(&public_key_path);

        if private_key_exists && public_key_exists {
            let mut private_key_file = File::open(&private_key_path)?;
            let mut private_key_pem = Vec::new();
            private_key_file.read_to_end(&mut private_key_pem)?;

            let mut public_key_file = File::open(&public_key_path)?;
            let mut public_key_pem = Vec::new();
            public_key_file.read_to_end(&mut public_key_pem)?;

            let pair = EcKey::private_key_from_pem(&private_key_pem)?;
            let public_key_bytes = Crypto::ec_get_public_key_bytes(&pair, curve)?;
            keys.insert(
                (*algo_name).to_owned(),
                EcHostKey {
                    ec_pair: pair,
                    public_key_bytes,
                },
            );
        } else {
            let pair = Crypto::ec_generate_host_key(curve)?;
            let public_key_bytes = Crypto::ec_get_public_key_bytes(&pair, curve)?;

            if private_key_exists {
                fs::remove_file(&private_key_path).context("Failed removing private key file")?;
                debug!("Removed private key file {:?}", private_key_path);
            }
            let mut private_key_file = File::create_new(&private_key_path)
                .context("Failed creating new private key file")?;
            private_key_file.write_all(&pair.private_key_to_pem()?)?;
            fs::set_permissions(&private_key_path, Permissions::from_mode(0o600))?; // owner: rw
            debug!("Created private key file {:?}", private_key_path);

            if public_key_exists {
                fs::remove_file(&public_key_path).context("Failed removing public key file")?;
                debug!("Removed public key file {:?}", public_key_path);
            }
            let mut public_key_file = File::create_new(&public_key_path)
                .context("Failed creating new private key file")?;
            public_key_file.write_all(&pair.public_key_to_pem()?)?;
            fs::set_permissions(&public_key_path, Permissions::from_mode(0o644))?; // owner: rw, group: r, other: r
            debug!("Created public key file {:?}", public_key_path);

            keys.insert(
                (*algo_name).to_owned(),
                EcHostKey {
                    ec_pair: pair,
                    public_key_bytes,
                },
            );
        }
    }

    Ok(keys)
}

fn get_server_algorithms() -> ServerAlgorithms {
    ServerAlgorithms {
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
    }
}
