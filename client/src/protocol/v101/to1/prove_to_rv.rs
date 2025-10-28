use coset::{CoseSign1, TaggedCborSerializable};

use crate::protocol::v101::{ClientMessage, Message, Msgtype};

use super::rv_redirect::RvRedirect;

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ProveToRv {
    pub(crate) ea_token: CoseSign1,
}

impl Message for ProveToRv {
    const MSG_TYPE: Msgtype = 32;

    fn decode(buf: &[u8]) -> eyre::Result<Self> {
        let ea_token = CoseSign1::from_tagged_slice(buf)?;

        // TODO: probably some validation is required here
        Ok(Self { ea_token })
    }

    fn encode(&self) -> eyre::Result<Vec<u8>> {
        // coset requires allocations
        let buf = self.ea_token.clone().to_tagged_vec()?;

        Ok(buf)
    }
}

impl ClientMessage for ProveToRv {
    type Response<'a> = RvRedirect;
}
