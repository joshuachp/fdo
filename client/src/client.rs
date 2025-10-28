use eyre::{OptionExt, WrapErr, eyre};
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, HeaderMap, HeaderName, HeaderValue};
use tracing::debug;
use url::Url;

use crate::protocol::latest::Msgtype;
use crate::protocol::latest::error::ErrorMessage;
use crate::protocol::v101::{ClientMessage, IntialMessage, Message, PROTOCOL_VERSION, Protver};

const MIME: HeaderValue = HeaderValue::from_static("application/cbor");
const MESSAGE_TYPE: HeaderName = HeaderName::from_static("message-type");

#[derive(Debug)]
pub(crate) struct NeedsAuth {}

#[derive(Debug)]
pub(crate) struct Client<A = HeaderValue> {
    auth: A,
    base_url: Url,
    protocol_version: Protver,
    client: reqwest::Client,
}

impl<A> Client<A> {
    async fn send<T>(&self, msg: &T, auth: Option<&HeaderValue>) -> eyre::Result<reqwest::Response>
    where
        T: ClientMessage,
    {
        let url = self.base_url.join(&format!(
            "/fdo/{}/msg/{}",
            self.protocol_version,
            T::MSG_TYPE
        ))?;

        debug!(%url, "sending message");

        let buff = msg.encode()?;

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

        // TODO: should check the error code
        if msg_type == ErrorMessage::MSG_TYPE {
            let bytes = response.bytes().await?;
            let bytes = std::io::Cursor::new(&bytes);

            let error: ErrorMessage = ciborium::from_reader(bytes)?;

            return Err(eyre!("error message: {error}"));
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

    pub async fn parse_msg<T>(resp: reqwest::Response) -> eyre::Result<T>
    where
        T: Message,
    {
        let bytes = resp.bytes().await?;

        let value = T::decode(&bytes)?;

        Ok(value)
    }
}

impl Client<NeedsAuth> {
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
            auth: NeedsAuth {},
        })
    }

    pub(crate) async fn init<T>(&self, msg: &T) -> eyre::Result<(T::Response<'static>, HeaderValue)>
    where
        T: IntialMessage,
    {
        let resp = self.send(msg, None).await?;

        let mut auth = resp
            .headers()
            .get(AUTHORIZATION)
            .ok_or_eyre("missing authorization header")?
            .clone();

        auth.set_sensitive(true);

        let msg = Self::parse_msg(resp).await?;

        Ok((msg, auth))
    }

    pub(crate) fn set_auth(self, auth: HeaderValue) -> Client {
        Client {
            auth,
            base_url: self.base_url,
            protocol_version: self.protocol_version,
            client: self.client,
        }
    }
}

impl Client<HeaderValue> {
    pub(crate) async fn send_msg<T>(&self, msg: &T) -> eyre::Result<T::Response<'static>>
    where
        T: ClientMessage,
    {
        let resp = self.send(msg, Some(&self.auth)).await?;

        Self::parse_msg(resp).await
    }
}
