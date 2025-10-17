use std::borrow::Cow;
use std::fmt::Debug;

use eyre::bail;
use serde::{Deserialize, Serialize};
use serde_bytes::Bytes;

use crate::protocol::Hex;

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct PublicKey<'a> {
    pk_type: PkType,
    pk_enc: PkType,
    pk_body: Cow<'a, Bytes>,
}

impl Debug for PublicKey<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self {
            pk_type,
            pk_enc,
            pk_body,
        } = self;

        f.debug_struct("PublicKey")
            .field("pk_type", pk_type)
            .field("pk_enc", pk_enc)
            .field("pk_body", &Hex::new(pk_body))
            .finish()
    }
}

impl Serialize for PublicKey<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let Self {
            pk_type,
            pk_enc,
            pk_body,
        } = self;

        (pk_type, pk_enc, pk_body).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for PublicKey<'_> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let (pk_type, pk_enc, pk_body) = Deserialize::deserialize(deserializer)?;

        Ok(Self {
            pk_type,
            pk_enc,
            pk_body,
        })
    }
}

/// KeyType is an FDO pkType enum.
///
/// ```cddl
/// pkType = (
///     RSA2048RESTR: 1, ;; RSA 2048 with restricted key/exponent (PKCS1 1.5 encoding)
///     RSAPKCS:      5, ;; RSA key, PKCS1, v1.5
///     RSAPSS:       6, ;; RSA key, PSS
///     SECP256R1:    10, ;; ECDSA secp256r1 = NIST-P-256 = prime256v1
///     SECP384R1:    11, ;; ECDSA secp384r1 = NIST-P-384
/// )
/// ;; These are identical
/// SECP256R1 = (
///     NIST-P-256,
///     PRIME256V1
/// )
/// ;; These are identical
/// SECP384R1 = (
///     NIST-P-384
/// )
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "u8", into = "u8")]
#[repr(u8)]
pub(crate) enum PkType {
    /// RSA 2048 with restricted key/exponent (PKCS1 1.5 encoding)
    Rsa2048Restr = 1,
    // RSA key, PKCS1, v1.5
    RsaPkcs = 5,
    // RSA key, PSS
    RsaPss = 6,
    // ECDSA secp256r1 = NIST-P-256 = prime256v1
    Secp256R1 = 10,
    // ECDSA secp384r1 = NIST-P-384
    Secp384R1 = 11,
}

impl TryFrom<u8> for PkType {
    type Error = eyre::Report;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        let value = match value {
            1 => PkType::Rsa2048Restr,
            5 => PkType::RsaPkcs,
            6 => PkType::RsaPss,
            10 => PkType::Secp256R1,
            11 => PkType::Secp384R1,
            _ => bail!("value out of range: {value}"),
        };

        Ok(value)
    }
}

impl From<PkType> for u8 {
    fn from(value: PkType) -> Self {
        value as u8
    }
}

/// Encoding of the PublicKey body
///
/// ```cddl
/// pkEnc = (
///     Crypto:       0      ;; applies to crypto with its own encoding (e.g., Intel® EPID)
///     X509:         1,     ;; X509 DER encoding, applies to RSA and ECDSA
///     X5CHAIN:      2,     ;; COSE x5chain, an ordered chain of X.509 certificates
///     COSEKEY:      3      ;; COSE key encoding
/// )
/// ```
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(try_from = "u8", into = "u8")]
#[repr(u8)]
pub(crate) enum PkEnc {
    /// Applies to crypto with its own encoding (e.g., Intel® EPID)
    Crypto = 0,
    /// X509 DER encoding, applies to RSA and ECDSA
    X509 = 1,
    /// COSE x5chain, an ordered chain of X.509 certificates
    X5Chain = 2,
    /// COSE key encoding
    CoseKey = 3,
}

impl TryFrom<u8> for PkEnc {
    type Error = eyre::Report;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        let value = match value {
            0 => PkEnc::Crypto,
            1 => PkEnc::X509,
            2 => PkEnc::X5Chain,
            3 => PkEnc::CoseKey,
            _ => bail!("value out of range: {value}"),
        };

        Ok(value)
    }
}

impl From<PkEnc> for u8 {
    fn from(value: PkEnc) -> Self {
        value as u8
    }
}
