use serde::{Deserialize, Serialize};

use crate::protocol::v101::{Message, Msgtype};

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Done;

impl Serialize for Done {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let Self {} = self;

        const EMPTY: [ciborium::Value; 0] = [];

        EMPTY.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Done {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let []: [ciborium::Value; 0] = Deserialize::deserialize(deserializer)?;

        Ok(Self {})
    }
}

impl Message for Done {
    const MSG_TYPE: Msgtype = 13;

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
