use serde::{Deserialize, Serialize};

use crate::protocol::CborBstr;
use crate::protocol::v101::{ClientMessage, IntialMessage, Message, Msgtype};

use super::set_credentials::SetCredentials;

#[derive(Debug)]
pub(crate) struct AppStart<T> {
    device_mfg_info: CborBstr<T>,
}

impl<T> AppStart<T> {
    pub(crate) fn new(device_mfg_info: T) -> Self {
        Self {
            device_mfg_info: CborBstr::new(device_mfg_info),
        }
    }
}

impl<T> Serialize for AppStart<T>
where
    T: Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let Self { device_mfg_info } = self;

        (device_mfg_info,).serialize(serializer)
    }
}

impl<'de, T> Deserialize<'de> for AppStart<T>
where
    T: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let (device_mfg_info,) = Deserialize::deserialize(deserializer)?;

        Ok(Self { device_mfg_info })
    }
}

impl<T> Message for AppStart<T>
where
    T: Serialize,
    for<'a> T: Deserialize<'a>,
{
    const MSG_TYPE: Msgtype = 10;

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

impl<T> ClientMessage for AppStart<T>
where
    T: Serialize,
    for<'de> T: Deserialize<'de>,
{
    type Response<'a> = SetCredentials<'a>;
}

impl<T> IntialMessage for AppStart<T>
where
    T: Serialize,
    for<'de> T: Deserialize<'de>,
{
}
