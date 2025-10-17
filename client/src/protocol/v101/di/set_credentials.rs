use serde::{Deserialize, Serialize};

use crate::Message;
use crate::protocol::CborBstr;
use crate::protocol::v101::Msgtype;
use crate::protocol::v101::ownership_voucher::OvHeader;

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct SetCredentials<'a> {
    pub(crate) ov_header: CborBstr<OvHeader<'a>>,
}

impl<'a> SetCredentials<'a> {
    pub(crate) fn ov_header(&self) -> &OvHeader<'a> {
        &self.ov_header.value
    }
}

impl Serialize for SetCredentials<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let Self { ov_header } = self;

        (ov_header,).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for SetCredentials<'_> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let (ov_header,) = Deserialize::deserialize(deserializer)?;

        Ok(Self { ov_header })
    }
}

impl Message for SetCredentials<'_> {
    const MSG_TYPE: Msgtype = 11;
}
