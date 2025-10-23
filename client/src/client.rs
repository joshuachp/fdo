use eyre::{OptionExt, WrapErr, eyre};
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, HeaderMap, HeaderName, HeaderValue};
use url::Url;

use crate::protocol::latest::Msgtype;
use crate::protocol::latest::error::ErrorMessage;
use crate::protocol::v101::{ClientMessage, Message, PROTOCOL_VERSION, Protver};

const MIME: HeaderValue = HeaderValue::from_static("application/cbor");
const MESSAGE_TYPE: HeaderName = HeaderName::from_static("message-type");

pub(crate) struct Client {
    base_url: Url,
    protocol_version: Protver,
    client: reqwest::Client,
}

impl Client {
    pub(crate) fn new(base_url: Url) -> eyre::Result<Self> {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, MIME);

        let client = reqwest::ClientBuilder::new()
            .default_headers(headers)
            .redirect(reqwest::redirect::Policy::none())
            .build()?;

        Ok(Self {
            base_url,
            protocol_version: PROTOCOL_VERSION,
            client,
        })
    }

    pub(crate) async fn send<T>(
        &self,
        msg: &T,
        auth: Option<&HeaderValue>,
    ) -> eyre::Result<reqwest::Response>
    where
        T: ClientMessage,
    {
        let url = self.base_url.join(&format!(
            "/fdo/{}/msg/{}",
            self.protocol_version,
            T::MSG_TYPE
        ))?;

        let mut buff = Vec::new();
        ciborium::into_writer(&msg, &mut buff)?;

        let mut req = self.client.post(url).header(MESSAGE_TYPE, T::MSG_TYPE);

        if let Some(token) = auth {
            req = req.header(AUTHORIZATION, token);
        }

        let response = req.body(buff).send().await?.error_for_status()?;

        let msg_type = response
            .headers()
            .get(MESSAGE_TYPE)
            .ok_or_eyre("missing message type header in response")
            .and_then(|msg_type| {
                let msg_type = msg_type.to_str().wrap_err("invalid UTF-8")?;
                let msg_type: Msgtype = msg_type
                    .parse()
                    .wrap_err_with(|| format!("couldn't parse message-type: {msg_type}"))?;

                Ok(msg_type)
            })?;

        if msg_type == ErrorMessage::MSG_TYPE {
            let bytes = response.bytes().await?;
            let bytes = std::io::Cursor::new(&bytes);

            let error: ErrorMessage = ciborium::from_reader(bytes)?;

            return Err(eyre!("error message: {error:?}"));
        }

        if msg_type != T::Response::MSG_TYPE {
            return Err(eyre!(
                "response message-type mismatch, expected {} but got {msg_type}",
                T::Response::MSG_TYPE
            ));
        }

        debug_assert!(
            auth.is_none() || response.headers().get(AUTHORIZATION) == auth,
            "AUTHORIZATION token mismatch"
        );

        Ok(response)
    }

    pub(crate) async fn send_msg<T>(
        &self,
        msg: &T,
        token: &HeaderValue,
    ) -> eyre::Result<T::Response<'static>>
    where
        T: ClientMessage,
    {
        let resp = self.send(msg, Some(token)).await?;

        Self::parse_msg(resp).await
    }

    pub async fn parse_msg<T>(resp: reqwest::Response) -> eyre::Result<T>
    where
        T: Message,
    {
        let bytes = resp.bytes().await?;

        let value = ciborium::from_reader(std::io::Cursor::new(bytes))?;

        Ok(value)
    }
}
