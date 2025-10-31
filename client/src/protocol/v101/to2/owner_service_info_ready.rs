use eyre::Context;
use serde::{Deserialize, Serialize};

use crate::protocol::v101::{Message, Msgtype};

/// ```cddl
/// TO2.OwnerServiceInfoReady  = [
///     maxDeviceServiceInfoSz    ;; maximum size service info that Owner can receive
/// ]
/// maxDeviceServiceInfoSz = uint16 / null
/// ```
pub(crate) struct OwnerServiceInfoReady {
    pub(crate) max_device_service_info_sz: Option<u16>,
}

impl Serialize for OwnerServiceInfoReady {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let Self {
            max_device_service_info_sz,
        } = self;

        (max_device_service_info_sz,).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for OwnerServiceInfoReady {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let (max_device_service_info_sz,) = Deserialize::deserialize(deserializer)?;

        Ok(Self {
            max_device_service_info_sz,
        })
    }
}

impl Message for OwnerServiceInfoReady {
    const MSG_TYPE: Msgtype = 67;

    fn decode(buf: &[u8]) -> eyre::Result<Self> {
        ciborium::from_reader(buf).wrap_err("couldn't decode TO2.OwnerServiceInfoReady")
    }

    fn encode(&self) -> eyre::Result<Vec<u8>> {
        let mut buf = Vec::new();

        ciborium::into_writer(self, &mut buf)?;

        Ok(buf)
    }
}
