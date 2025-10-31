use std::borrow::Cow;

use serde::{Deserialize, Serialize};

use crate::protocol::v101::sign_info::EASigInfo;
use crate::protocol::v101::{
    ClientMessage, Guid, IntialMessage, Message, Msgtype, NonceTo2ProveOv,
};

use super::prove_ov_hdr::ProveOvHdr;

/// ```cddl
/// TO2.HelloDevice = [
///     maxDeviceMessageSize,
///     Guid,
///     NonceTO2ProveOV,
///     kexSuiteName,
///     cipherSuiteName,
///     eASigInfo  ;; Device attestation signature info
/// ]
/// maxDeviceMessageSize = uint16
/// kexSuiteName = tstr
/// cipherSuiteName = CipherSuites
/// ```
#[derive(Debug)]
pub(crate) struct HelloDevice<'a> {
    pub(crate) max_device_message_size: u16,
    pub(crate) guid: Guid,
    pub(crate) nonce: NonceTo2ProveOv,
    pub(crate) kex_suite_name: Cow<'a, str>,
    pub(crate) cipher_suite_name: i64,
    pub(crate) ea_sign_info: EASigInfo<'a>,
}

impl Serialize for HelloDevice<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let Self {
            max_device_message_size,
            guid,
            nonce,
            kex_suite_name,
            cipher_suite_name,
            ea_sign_info,
        } = self;

        (
            max_device_message_size,
            guid,
            nonce,
            kex_suite_name,
            cipher_suite_name,
            ea_sign_info,
        )
            .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for HelloDevice<'_> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let (max_device_message_size, guid, nonce, kex_suite_name, cipher_suite_name, ea_sign_info) =
            Deserialize::deserialize(deserializer)?;

        Ok(Self {
            max_device_message_size,
            guid,
            nonce,
            kex_suite_name,
            cipher_suite_name,
            ea_sign_info,
        })
    }
}

impl Message for HelloDevice<'_> {
    const MSG_TYPE: Msgtype = 60;

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

impl ClientMessage for HelloDevice<'_> {
    type Response<'a> = ProveOvHdr;
}

impl IntialMessage for HelloDevice<'_> {}
