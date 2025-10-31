use serde::{Deserialize, Serialize};

use crate::protocol::v101::ownership_voucher::OvEntry;
use crate::protocol::v101::{Message, Msgtype};

/// ```cddl
/// TO2.GetOVNextEntry = [
///     OVEntryNum
/// ]
/// OVEntryNum = uint8
/// ```
#[derive(Debug)]
pub(crate) struct OvNextEntry {
    pub(crate) ov_entry_num: u8,
    pub(crate) ov_entry: OvEntry,
}

impl Serialize for OvNextEntry {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let Self {
            ov_entry_num,
            ov_entry,
        } = self;

        (ov_entry_num, ov_entry).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for OvNextEntry {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let (ov_entry_num, ov_entry) = Deserialize::deserialize(deserializer)?;

        Ok(Self {
            ov_entry_num,
            ov_entry,
        })
    }
}

impl Message for OvNextEntry {
    const MSG_TYPE: Msgtype = 63;

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
