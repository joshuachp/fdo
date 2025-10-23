use serde::Serialize;
use serde::de::DeserializeOwned;

pub(crate) mod device_credentials;
pub(crate) mod di;
pub(crate) mod error;
pub(crate) mod guid;
pub(crate) mod hash_hmac;
pub(crate) mod ownership_voucher;
pub(crate) mod public_key;
pub(crate) mod randezvous_info;

// Type names used in the specification
pub(crate) type Protver = u16;
pub(crate) type Msglen = u16;
pub(crate) type Msgtype = u16;

pub(crate) const PROTOCOL_VERSION_MAJOR: Protver = 1;
pub(crate) const PROTOCOL_VERSION_MINOR: Protver = 1;
pub(crate) const PROTOCOL_VERSION: Protver = PROTOCOL_VERSION_MAJOR * 100 + PROTOCOL_VERSION_MINOR;

pub(crate) trait Message: Serialize + DeserializeOwned {
    const MSG_TYPE: Msgtype;
}

pub(crate) trait ClientMessage: Message {
    type Response<'a>: Message;
}
