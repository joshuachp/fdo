use std::borrow::Cow;
use std::fmt::{Debug, Display};
use std::ops::Deref;

use once_cell::sync::OnceCell;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_bytes::{ByteBuf, Bytes};
use tracing::debug;

pub(crate) use self::v101 as latest;
pub(crate) mod v101;

pub(crate) mod di;
pub(crate) mod to1;
pub(crate) mod to2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CborBstr<'a, T> {
    bytes: OnceCell<Cow<'a, Bytes>>,
    value: T,
}

impl<'a, T> CborBstr<'a, T> {
    pub(crate) fn new(value: T) -> Self {
        Self {
            bytes: OnceCell::default(),
            value,
        }
    }

    pub(crate) fn bytes(&self) -> eyre::Result<&Cow<'a, Bytes>>
    where
        T: Serialize,
    {
        let foo = self
            .bytes
            .get_or_try_init(|| -> eyre::Result<Cow<'a, Bytes>> {
                debug!("initializing encoded cbor bstr");

                let mut buf = Vec::new();

                ciborium::into_writer(&self.value, &mut buf)?;

                debug!(len = buf.len());

                Ok(Cow::Owned(buf.into()))
            })?;

        Ok(foo)
    }
}

impl<'a, T> Deref for CborBstr<'a, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

impl<'a, T> Serialize for CborBstr<'a, T>
where
    T: Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let bytes = self.bytes().map_err(serde::ser::Error::custom)?;

        bytes.serialize(serializer)
    }
}

impl<'a, 'de, T> Deserialize<'de> for CborBstr<'a, T>
where
    T: DeserializeOwned,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes = ByteBuf::deserialize(deserializer)?;

        let value: T = ciborium::from_reader(bytes.as_slice()).map_err(serde::de::Error::custom)?;

        Ok(CborBstr {
            value,
            bytes: OnceCell::with_value(Cow::Owned(bytes)),
        })
    }
}

pub(crate) type OneOrMore<T> = Repetition<1, T>;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct Repetition<const MIN: usize, T>(Vec<T>);

impl<const MIN: usize, T> Repetition<MIN, T> {
    const _ASSET: () = assert!(MIN > 0, "MIN must be greater than 0");

    pub(crate) fn new(values: Vec<T>) -> Option<Self> {
        (values.len() >= MIN).then_some(Self(values))
    }

    pub(crate) fn first(&self) -> &T {
        debug_assert!(!self.0.is_empty());
        // Safety: this structure must have at least MIN elements and MIN is checked at compile time
        //         to be grater than 0
        unsafe { self.0.get_unchecked(0) }
    }
}

impl<const MIN: usize, T> Deref for Repetition<MIN, T> {
    type Target = Vec<T>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<const MIN: usize, T> Serialize for Repetition<MIN, T>
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

impl<'de, const MIN: usize, T> Deserialize<'de> for Repetition<MIN, T>
where
    T: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let values = Vec::deserialize(deserializer)?;

        Self::new(values)
            .ok_or_else(|| serde::de::Error::invalid_length(0, &MIN.to_string().as_str()))
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
