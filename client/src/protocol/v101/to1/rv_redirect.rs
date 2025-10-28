use coset::{CoseSign1, TaggedCborSerializable};
use eyre::{OptionExt, ensure};
use serde::{Deserialize, Serialize};

use crate::protocol::v101::hash_hmac::Hash;
use crate::protocol::v101::rv_to2_addr::RvTo2Addr;
use crate::protocol::v101::{Message, Msgtype};

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct RvRedirect {
    pub(crate) to1d: CoseSign1,
}

impl RvRedirect {
    pub(crate) fn rv_to2_addr(&self) -> eyre::Result<To1dBlob<'_>> {
        let payload = self.to1d.payload.as_ref().ok_or_eyre("payload misisng")?;

        let rv_addr = ciborium::from_reader(payload.as_slice())?;

        Ok(rv_addr)
    }
}

impl Message for RvRedirect {
    const MSG_TYPE: Msgtype = 33;

    fn decode(buf: &[u8]) -> eyre::Result<Self> {
        let to1d = CoseSign1::from_tagged_slice(buf)?;

        ensure!(to1d.payload.is_some(), "to1d payload missing");

        Ok(Self { to1d })
    }

    fn encode(&self) -> eyre::Result<Vec<u8>> {
        let buf = self.to1d.clone().to_tagged_vec()?;

        Ok(buf)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct To1dBlob<'a> {
    to1d_rv: RvTo2Addr<'a>,
    to1d_to0d_hash: Hash<'a>,
}

impl Serialize for To1dBlob<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let Self {
            to1d_rv,
            to1d_to0d_hash,
        } = self;

        (to1d_rv, to1d_to0d_hash).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for To1dBlob<'_> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let (to1d_rv, to1d_to0d_hash) = Deserialize::deserialize(deserializer)?;

        Ok(Self {
            to1d_rv,
            to1d_to0d_hash,
        })
    }
}
