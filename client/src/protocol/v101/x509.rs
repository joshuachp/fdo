use std::borrow::Cow;
use std::fmt::Debug;

use serde::{Deserialize, Serialize};
use serde_bytes::Bytes;

use crate::protocol::{Hex, Repetition};

/// From COSE RFC
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
// TODO: could be better
#[serde(untagged)]
pub(crate) enum CoseX509<'a> {
    // TODO: should be 2, this is not spec complaint
    Certs(Repetition<1, X509<'a>>),
    One(X509<'a>),
}

impl<'a> CoseX509<'a> {
    /// Returns `true` if the cose x509 is [`One`].
    ///
    /// [`One`]: CoseX509::One
    #[must_use]
    pub(crate) fn is_one(&self) -> bool {
        matches!(self, Self::One(..))
    }

    pub(crate) fn cert_key(&self) -> &[u8] {
        let cert = match self {
            CoseX509::Certs(repetition) => repetition.first(),
            CoseX509::One(cow) => cow,
        };

        cert.key()
    }
}

#[derive(Clone, Eq)]
pub(crate) struct X509<'a> {
    cert: Cow<'a, Bytes>,
    key: Vec<u8>,
}

impl<'a> X509<'a> {
    pub(crate) fn key(&self) -> &[u8] {
        &self.key
    }
}

impl Serialize for X509<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.cert.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for X509<'_> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let cert: Cow<'_, Bytes> = Deserialize::deserialize(deserializer)?;

        let (rest, parsed) =
            x509_parser::parse_x509_certificate(&cert).map_err(serde::de::Error::custom)?;

        debug_assert!(rest.is_empty());

        Ok(Self {
            key: parsed.subject_pki.raw.to_vec(),
            cert,
        })
    }
}

impl Debug for X509<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self { cert, key } = self;

        f.debug_struct("X509")
            .field("cert", &Hex::new(cert))
            .field("key", &Hex::new(key))
            .finish()
    }
}

impl PartialEq for X509<'_> {
    fn eq(&self, other: &Self) -> bool {
        let Self { cert, key: _ } = self;

        *cert == other.cert
    }
}
