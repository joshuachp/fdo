use eyre::Context;
use serde::{Deserialize, Serialize};

use crate::protocol::v101::service_info::ServiceInfo;
use crate::protocol::v101::{Message, Msgtype};

/// ```cddl
/// TO2.OwnerServiceInfo = [
///     IsMoreServiceInfo,
///     IsDone,
///     ServiceInfo
/// ]
/// IsDone = bool
/// ```
#[derive(Debug)]
pub(crate) struct OwnerServiceInfo<'a> {
    pub(crate) is_more_service_info: bool,
    pub(crate) is_done: bool,
    pub(crate) service_info: ServiceInfo<'a>,
}

impl Serialize for OwnerServiceInfo<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let Self {
            is_more_service_info,
            is_done,
            service_info,
        } = self;

        (is_more_service_info, is_done, service_info).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for OwnerServiceInfo<'_> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let (is_more_service_info, is_done, service_info) = Deserialize::deserialize(deserializer)?;

        Ok(Self {
            is_more_service_info,
            is_done,
            service_info,
        })
    }
}

impl Message for OwnerServiceInfo<'_> {
    const MSG_TYPE: Msgtype = 69;

    fn decode(buf: &[u8]) -> eyre::Result<Self> {
        ciborium::from_reader(buf).wrap_err("couldn't decode TO2.OwnerServiceInfo")
    }

    fn encode(&self) -> eyre::Result<Vec<u8>> {
        let mut buf = Vec::new();

        ciborium::into_writer(self, &mut buf)?;

        Ok(buf)
    }
}
