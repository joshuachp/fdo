use std::fmt::{Debug, Display};
use std::ops::Deref;

use serde::{Deserialize, Serialize};
use serde_bytes::{ByteBuf, Bytes};
use url::Url;

use crate::client::Client;

pub(crate) use self::v101 as latest;
pub(crate) mod v101;

pub(crate) mod di;

// TODO:
//   - error handling
//   - back off
//   - single step retry
//   - full retry
pub(crate) struct Ctx<C> {
    client: Client,
    crypto: C,
}

impl<C> Ctx<C> {
    pub(crate) fn create(base_url: Url, crypto: C) -> eyre::Result<Self> {
        let client = Client::new(base_url)?;

        Ok(Self { client, crypto })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct CborBstr<T> {
    value: T,
}

impl<T> CborBstr<T> {
    pub(crate) fn new(value: T) -> Self {
        Self { value }
    }

    pub(crate) fn value(&self) -> &T {
        &self.value
    }
}

impl<T> Serialize for CborBstr<T>
where
    T: Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut buff = Vec::new();

        ciborium::into_writer(self.value(), &mut buff).map_err(serde::ser::Error::custom)?;

        Bytes::new(&buff).serialize(serializer)
    }
}

impl<'de, T> Deserialize<'de> for CborBstr<T>
where
    T: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes = ByteBuf::deserialize(deserializer)?;

        let value: ciborium::Value = ciborium::from_reader(std::io::Cursor::new(&bytes))
            .map_err(serde::de::Error::custom)?;

        let value = value.deserialized().map_err(serde::de::Error::custom)?;

        Ok(CborBstr::new(value))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct OneOrMore<T>(Vec<T>);

impl<T> Deref for OneOrMore<T> {
    type Target = Vec<T>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> Serialize for OneOrMore<T>
where
    T: Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de, T> Deserialize<'de> for OneOrMore<T>
where
    T: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let values = Vec::deserialize(deserializer)?;

        if values.is_empty() {
            return Err(serde::de::Error::invalid_length(0, &"one or more"));
        }

        Ok(Self(values))
    }
}

pub(crate) struct Hex<'a>(&'a [u8]);

impl<'a> Hex<'a> {
    pub(crate) fn new(items: &'a [u8]) -> Self {
        Self(items)
    }
}

impl Debug for Hex<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&self, f)
    }
}

impl Display for Hex<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }

        Ok(())
    }
}
