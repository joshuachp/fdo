use serde::{Deserialize, Serialize};

use crate::protocol::v101::hash_hmac::HMac;
use crate::protocol::v101::{ClientMessage, Message, Msgtype};

use super::done::Done;

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct SetHmac<'a> {
    pub(crate) hmac: HMac<'a>,
}

impl Serialize for SetHmac<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let Self { hmac } = self;

        (hmac,).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for SetHmac<'_> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let (hmac,) = Deserialize::deserialize(deserializer)?;

        Ok(Self { hmac })
    }
}

impl Message for SetHmac<'_> {
    const MSG_TYPE: Msgtype = 12;
}

impl ClientMessage for SetHmac<'_> {
    type Response<'a> = Done;
}
