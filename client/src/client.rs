use std::marker::PhantomData;

use coset::{CoseEncrypt0, TaggedCborSerializable};
use eyre::{OptionExt, WrapErr, eyre};
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, HeaderMap, HeaderName, HeaderValue};
use tracing::{debug, error};
use url::Url;

use crate::Ctx;
use crate::crypto::Crypto;
use crate::protocol::latest::Msgtype;
use crate::protocol::latest::error::ErrorMessage;
use crate::protocol::v101::{ClientMessage, IntialMessage, Message, PROTOCOL_VERSION, Protver};

const MIME: HeaderValue = HeaderValue::from_static("application/cbor");
const MESSAGE_TYPE: HeaderName = HeaderName::from_static("message-type");

#[derive(Debug)]
pub(crate) struct NeedsAuth {}

#[derive(Debug)]
pub(crate) struct NeedsEncryption {}

#[derive(Debug)]
pub(crate) struct Client<A = HeaderValue, E = NeedsEncryption> {
    auth: A,
    base_url: Url,
    protocol_version: Protver,
    client: reqwest::Client,
    key: E,
}

impl<A, E> Client<A, E> {
    async fn send<T>(&self, msg: &T, auth: Option<&HeaderValue>) -> eyre::Result<reqwest::Response>
    where
        T: Message,
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

        Ok(response)
    }

    async fn send_with_resp<T>(
        &self,
        msg: &T,
        auth: Option<&HeaderValue>,
    ) -> eyre::Result<reqwest::Response>
    where
        T: ClientMessage,
    {
        let response = self.send(msg, auth).await?;

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

            let error: ErrorMessage = ciborium::from_reader(bytes.as_ref())?;

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

    async fn parse_msg<T>(resp: reqwest::Response) -> eyre::Result<T>
    where
        T: Message,
    {
        let bytes = resp.bytes().await?;

        let value = T::decode(&bytes)?;

        Ok(value)
    }

    async fn parse_enc_msg<T, C, S>(
        _ctx: &mut Ctx<'_, C, S>,
        key: &C::KeyExchange,
        resp: reqwest::Response,
    ) -> eyre::Result<T>
    where
        C: Crypto,
        T: Message,
    {
        let bytes = resp.bytes().await?;

        let enc =
            CoseEncrypt0::from_tagged_slice(&bytes).wrap_err("couldn't decode encrypt message")?;

        let plain = C::cose_decrypt(&enc, key).wrap_err("couldn't decrypt encripted msg")?;

        T::decode(&plain).wrap_err("couldn't decode message body")
    }
}

impl Client<NeedsAuth, NeedsEncryption> {
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
            key: NeedsEncryption {},
        })
    }

    pub(crate) async fn init<T>(&self, msg: &T) -> eyre::Result<(T::Response<'static>, HeaderValue)>
    where
        T: IntialMessage,
    {
        let resp = self.send_with_resp(msg, None).await?;

        let mut auth = resp
            .headers()
            .get(AUTHORIZATION)
            .ok_or_eyre("missing authorization header")?
            .clone();

        auth.set_sensitive(true);

        let msg = Self::parse_msg(resp).await?;

        Ok((msg, auth))
    }

    pub(crate) fn set_auth(self, auth: HeaderValue) -> Client<HeaderValue, NeedsEncryption> {
        Client {
            auth,
            base_url: self.base_url,
            protocol_version: self.protocol_version,
            client: self.client,
            key: self.key,
        }
    }
}

impl Client<HeaderValue, NeedsEncryption> {
    pub(crate) async fn send_msg<T>(&self, msg: &T) -> eyre::Result<T::Response<'static>>
    where
        T: ClientMessage,
    {
        let resp = self.send_with_resp(msg, Some(&self.auth)).await?;

        Self::parse_msg(resp).await
    }

    pub(crate) async fn send_err(&self, msg: &ErrorMessage<'_>) -> bool {
        if let Err(err) = self.send(msg, Some(&self.auth)).await {
            error!(error = format!("{err:#}"), "couldn't send error message");

            return false;
        }

        true
    }

    pub fn set_enckey<E>(self, key: E) -> Client<HeaderValue, E> {
        Client {
            auth: self.auth,
            base_url: self.base_url,
            protocol_version: self.protocol_version,
            client: self.client,
            key,
        }
    }

    pub(crate) async fn init_enc<T, C, S>(
        &self,
        ctx: &mut Ctx<'_, C, S>,
        key: &C::KeyExchange,
        msg: &T,
    ) -> eyre::Result<T::Response<'static>>
    where
        C: Crypto,
        T: ClientMessage,
    {
        let resp = self.send_with_resp(msg, Some(&self.auth)).await?;

        Self::parse_enc_msg(ctx, key, resp).await
    }
}

impl<E> Client<HeaderValue, E> {
    pub(crate) async fn send_enc<T, C, S>(
        &self,
        ctx: &mut Ctx<'_, C, S>,
        msg: &T,
    ) -> eyre::Result<T::Response<'static>>
    where
        C: Crypto<KeyExchange = E>,
        T: ClientMessage,
    {
        let msg = EncMessage::create(ctx, &self.key, msg)?;

        let resp = self.send_with_resp(&msg, Some(&self.auth)).await?;

        Self::parse_enc_msg(ctx, &self.key, resp).await
    }
}

struct EncMessage<T> {
    inner: CoseEncrypt0,
    _marker: PhantomData<T>,
}

impl<T> EncMessage<T> {
    fn create<C, S>(ctx: &mut Ctx<'_, C, S>, key: &C::KeyExchange, msg: &T) -> eyre::Result<Self>
    where
        T: Message,
        C: Crypto,
    {
        let payload = msg.encode()?;

        ctx.crypto.cose_encrypt(key, &payload).map(|inner| Self {
            inner,
            _marker: PhantomData,
        })
    }
}

impl<T> Message for EncMessage<T>
where
    T: Message,
{
    const MSG_TYPE: Msgtype = T::MSG_TYPE;

    fn decode(buf: &[u8]) -> eyre::Result<Self> {
        CoseEncrypt0::from_tagged_slice(buf)
            .map(|inner| EncMessage {
                inner,
                _marker: PhantomData,
            })
            .wrap_err("couldn't decode encrypted  ose")
    }

    fn encode(&self) -> eyre::Result<Vec<u8>> {
        self.inner
            .clone()
            .to_tagged_vec()
            .wrap_err("couldn't encode encrypted cose")
    }
}

impl<T> ClientMessage for EncMessage<T>
where
    T: ClientMessage,
{
    type Response<'a> = T::Response<'a>;
}
