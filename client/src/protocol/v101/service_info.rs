use std::borrow::Cow;

use serde::{Deserialize, Serialize};
use serde_bytes::Bytes;

use crate::protocol::CborBstr;

pub(crate) type ServiceInfo<'a> = Vec<ServiceInfoKv<'a>>;

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ServiceInfoKv<'a> {
    pub(crate) service_info_key: Cow<'a, str>,
    // TODO: make generic
    pub(crate) service_info_val: CborBstr<'a, ciborium::Value>,
}

impl Serialize for ServiceInfoKv<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let Self {
            service_info_key,
            service_info_val,
        } = self;

        (service_info_key, service_info_val).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ServiceInfoKv<'_> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let (service_info_key, service_info_val) = Deserialize::deserialize(deserializer)?;

        Ok(Self {
            service_info_key,
            service_info_val,
        })
    }
}
