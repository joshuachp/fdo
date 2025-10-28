use serde::{Deserialize, Serialize};

use crate::protocol::v101::sign_info::EASigInfo;
use crate::protocol::v101::{ClientMessage, Guid, IntialMessage, Message, Msgtype};

use super::hello_rv_ack::HelloRvAck;

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct HelloRv<'a> {
    pub(crate) guid: Guid,
    pub(crate) e_a_sig_info: EASigInfo<'a>,
}

impl Serialize for HelloRv<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let Self { guid, e_a_sig_info } = self;

        (guid, e_a_sig_info).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for HelloRv<'_> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let (guid, e_a_sig_info) = Deserialize::deserialize(deserializer)?;

        Ok(Self { guid, e_a_sig_info })
    }
}

impl Message for HelloRv<'_> {
    const MSG_TYPE: Msgtype = 30;

    fn decode(buf: &[u8]) -> eyre::Result<Self> {
        let this = ciborium::from_reader(buf)?;

        Ok(this)
    }

    fn encode(&self) -> eyre::Result<Vec<u8>> {
        let mut buf = Vec::new();
        ciborium::into_writer(self, &mut buf)?;

        Ok(buf)
    }
}

impl ClientMessage for HelloRv<'_> {
    type Response<'a> = HelloRvAck<'a>;
}

impl IntialMessage for HelloRv<'_> {}
