use num_derive::FromPrimitive;
use openssl::{hash::MessageDigest, nid::Nid, symm::Cipher};

#[allow(non_camel_case_types)]
#[derive(FromPrimitive, Debug, PartialEq, Clone, Copy)]
pub enum MessageType {
    // Transport layer protocol:
    // 1 to 19 - Transport layer generic (e.g., disconnect, ignore, debug, etc.)
    SSH_MSG_DISCONNECT = 1,
    SSH_MSG_IGNORE = 2,
    SSH_MSG_UNIMPLEMENTED = 3,
    SSH_MSG_DEBUG = 4,
    SSH_MSG_SERVICE_REQUEST = 5,
    SSH_MSG_SERVICE_ACCEPT = 6,
    SSH_MSG_EXT_INFO = 7,

    // 20 to 29 - Algorithm negotiation
    SSH_MSG_KEXINIT = 20,
    SSH_MSG_NEWKEYS = 21,

    // 30 to 49 - Key exchange method specific (numbers can be reused for different authentication methods)
    SSH_MSG_KEX_ECDH_INIT = 30,
    SSH_MSG_KEX_ECDH_REPLY = 31,

    // User authentication protocol:
    // 50 to 59 - User authentication generic
    SSH_MSG_USERAUTH_REQUEST = 50,
    SSH_MSG_USERAUTH_FAILURE = 51,
    SSH_MSG_USERAUTH_SUCCESS = 52,
    SSH_MSG_USERAUTH_BANNER = 53,

    // 60 to 79 - User authentication method specific (numbers can be reused for different authentication methods)
    SSH_MSG_USERAUTH_PK_OK = 60,

    // Connection protocol:
    // 80 to 89 - Connection protocol generic
    SSH_MSG_GLOBAL_REQUEST = 80,
    SSH_MSG_REQUEST_SUCCESS = 81,
    SSH_MSG_REQUEST_FAILURE = 82,

    // 90 to 127 - Channel related messages
    SSH_MSG_CHANNEL_OPEN = 90,
    SSH_MSG_CHANNEL_OPEN_CONFIRMATION = 91,
    SSH_MSG_CHANNEL_OPEN_FAILURE = 92,
    SSH_MSG_CHANNEL_WINDOW_ADJUST = 93,
    SSH_MSG_CHANNEL_DATA = 94,
    SSH_MSG_CHANNEL_EXTENDED_DATA = 95,
    SSH_MSG_CHANNEL_EOF = 96,
    SSH_MSG_CHANNEL_CLOSE = 97,
    SSH_MSG_CHANNEL_REQUEST = 98,
    SSH_MSG_CHANNEL_SUCCESS = 99,
    SSH_MSG_CHANNEL_FAILURE = 100,
    // Reserved for client protocols:
    // 128 to 191 - Reserved

    // Local extensions:
    // 192 to 255 - Local extensions
}

#[allow(non_camel_case_types)]
#[derive(FromPrimitive, Debug, PartialEq, Clone, Copy)]
pub enum DisconnectReason {
    SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT = 1,
    SSH_DISCONNECT_PROTOCOL_ERROR = 2,
    SSH_DISCONNECT_KEY_EXCHANGE_FAILED = 3,
    SSH_DISCONNECT_RESERVED = 4,
    SSH_DISCONNECT_MAC_ERROR = 5,
    SSH_DISCONNECT_COMPRESSION_ERROR = 6,
    SSH_DISCONNECT_SERVICE_NOT_AVAILABLE = 7,
    SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED = 8,
    SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE = 9,
    SSH_DISCONNECT_CONNECTION_LOST = 10,
    SSH_DISCONNECT_BY_APPLICATION = 11,
    SSH_DISCONNECT_TOO_MANY_CONNECTIONS = 12,
    SSH_DISCONNECT_AUTH_CANCELLED_BY_USER = 13,
    SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE = 14,
    SSH_DISCONNECT_ILLEGAL_USER_NAME = 15,
}

macro_rules! def_enum {
    ($vis:vis $name:ident => $ty:ty {
        $($variant:ident => $val:expr),+
        $(,)?
    }) => {
        $vis struct $name;

        impl $name {
            $(
                pub const $variant: $ty = $val;
            )+

            #[allow(dead_code)]
            pub const VARIANTS: &'static [$ty] = &[$(Self::$variant),+];
        }
    };
}

#[macro_export]
macro_rules! hashmap {
    ($( $key: expr => $val: expr ),*) => {{
         let mut map = ::std::collections::HashMap::new();
         $( map.insert($key, $val); )*
         map
    }}
}

def_enum!(pub KexAlgorithm => &'static str {
    ECDH_SHA2_NISTP256 => "ecdh-sha2-nistp256",
    ECDH_SHA2_NISTP384 => "ecdh-sha2-nistp384",
    ECDH_SHA2_NISTP521 => "ecdh-sha2-nistp521",
    // RFC 8308 § 2.1
    EXT_INFO_C => "ext-info-c",
});
#[derive(Clone)]
pub struct KexAlgorithmDetails {
    pub hash: MessageDigest,
    pub curve: Nid,
}

def_enum!(pub HostKeyAlgorithm => &'static str {
    ECDSA_SHA2_NISTP256 => "ecdsa-sha2-nistp256",
    ECDSA_SHA2_NISTP384 => "ecdsa-sha2-nistp384",
    ECDSA_SHA2_NISTP521 => "ecdsa-sha2-nistp521",
});
#[derive(Clone)]
pub struct HostKeyAlgorithmDetails {
    pub hash: MessageDigest,
    pub curve: Nid,
}

def_enum!(pub EncryptionAlgorithm => &'static str {
    AES128_CTR => "aes128-ctr",
});
#[derive(Clone)]
pub struct EncryptionAlgorithmDetails {
    pub cipher: Cipher,
    pub block_size: usize,
}

def_enum!(pub HmacAlgorithm => &'static str {
   HMAC_SHA2_256 => "hmac-sha2-256",
});
#[derive(Clone)]
pub struct HmacAlgorithmDetails {
    pub hash: MessageDigest,
}

def_enum!(pub CompressionAlgorithm => &'static str {
    NONE => "none",
});
#[derive(Clone)]
pub struct CompressionAlgorithmDetails {}

def_enum!(pub ServiceName => &'static str {
    SSH_USERAUTH => "ssh-userauth",
    // SSH_CONNECTION => "ssh-connection",
});

def_enum!(pub AuthenticationMethod => &'static str {
    PUBLIC_KEY => "publickey",
    // PASSWORD => "password",
    // HOSTBASED => "hostbased",
    NONE => "none",
});
