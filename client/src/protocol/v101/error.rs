use std::borrow::Cow;

use serde::{Deserialize, Serialize};

use crate::Message;

use super::Msgtype;

#[derive(Debug, Clone)]
pub(crate) struct ErrorMessage<'a> {
    // Error code
    // TODO: error codes are well defined
    e_m_error_code: u16,
    // Message ID (type) of the previous message
    e_m_prev_msg_id: u8,
    // Error string
    e_m_error_str: Cow<'a, str>,
    // UTC timestamp
    e_m_error_ts: ciborium::Value,
    // Unique id associated with this request
    e_m_error_c_i_d: Option<u64>,
}

impl Serialize for ErrorMessage<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let Self {
            e_m_error_code,
            e_m_prev_msg_id,
            e_m_error_str,
            e_m_error_ts,
            e_m_error_c_i_d,
        } = self;

        (
            e_m_error_code,
            e_m_prev_msg_id,
            e_m_error_str,
            e_m_error_ts,
            e_m_error_c_i_d,
        )
            .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ErrorMessage<'_> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let (e_m_error_code, e_m_prev_msg_id, e_m_error_str, e_m_error_ts, e_m_error_c_i_d) =
            Deserialize::deserialize(deserializer)?;

        Ok(Self {
            e_m_error_code,
            e_m_prev_msg_id,
            e_m_error_str,
            e_m_error_ts,
            e_m_error_c_i_d,
        })
    }
}

impl Message for ErrorMessage<'_> {
    const MSG_TYPE: Msgtype = 255;
}
