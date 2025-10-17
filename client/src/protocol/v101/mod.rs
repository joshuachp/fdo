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
