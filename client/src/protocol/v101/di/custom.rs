use std::borrow::Cow;
use std::fmt::Debug;

use serde::{Deserialize, Serialize};
use serde_bytes::{ByteBuf, Bytes};

use crate::crypto::Crypto;
use crate::protocol::Hex;
use crate::protocol::v101::public_key::{PkEnc, PkType};

/// DeviceMfgInfo is an example structure for use in DI.AppStart. The structure
/// is not part of the spec, but matches the [C client] and [Java client]
/// implementations.
///
/// Type definition from C:
///
///    MfgInfo.cbor = [
///      pkType,                 // as per FDO spec
///      pkEnc,                  // as per FDO spec
///      serialNo,               // tstr
///      modelNo,                // tstr
///      CSR,                    // bstr
///      OnDie ECDSA cert chain, // bstr OR OMITTED
///      test signature,         // bstr OR OMITTED
///      MAROE prefix,           // bstr OR OMITTED
///    ]
///
///    DeviceMfgInfo = bstr, MfgInfo.cbor (bstr-wrap MfgInfo CBOR bytes)
///
/// [C client]: https://github.com/fido-device-onboard/client-sdk-fidoiot/
/// [Java client]: https://github.com/fido-device-onboard/pri-fidoiot
#[derive(Clone)]
pub(crate) struct MfgInfo<'a> {
    pk_type: PkType,
    pk_enc: PkEnc,
    serial_no: Cow<'a, str>,
    model_no: Cow<'a, str>,
    cert_info: Cow<'a, Bytes>,
    // odca_chain: Vec<u8>, // deprecated
    // test: Vec<u8>, // deprecated
    // maroe: Vec<u8>, // deprecated
}

impl<'a> MfgInfo<'a> {
    pub(crate) async fn generate<C>(
        crypto: &mut C,
        serial_no: &'a str,
        model_no: &'a str,
    ) -> eyre::Result<Self>
    where
        C: Crypto,
    {
        let csr = crypto.csr(model_no).await?;

        Ok(Self {
            pk_type: crypto.pk_type(),
            pk_enc: C::PK_ENC,
            serial_no: Cow::Borrowed(serial_no),
            model_no: Cow::Borrowed(model_no),
            cert_info: Cow::Owned(ByteBuf::from(csr)),
        })
    }
}

impl Debug for MfgInfo<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self {
            pk_type,
            pk_enc,
            serial_no,
            model_no,
            cert_info,
        } = self;
        f.debug_struct("MfgInfo")
            .field("pk_type", &pk_type)
            .field("pk_enc", &pk_enc)
            .field("serial_no", &serial_no)
            .field("model_no", &model_no)
            .field("cert_info", &Hex::new(cert_info))
            .finish()
    }
}

impl Serialize for MfgInfo<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let Self {
            pk_type,
            pk_enc,
            serial_no,
            model_no,
            cert_info,
        } = self;

        (pk_type, pk_enc, serial_no, model_no, cert_info).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for MfgInfo<'_> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let (pk_type, pk_enc, serial_no, model_no, cert_info) =
            Deserialize::deserialize(deserializer)?;

        Ok(Self {
            pk_type,
            pk_enc,
            serial_no,
            model_no,
            cert_info,
        })
    }
}
