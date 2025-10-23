use coset::{CborSerializable, CoseEncrypt0};
use eyre::OptionExt;
use reqwest::header::{AUTHORIZATION, HeaderValue};
use serde_bytes::ByteBuf;
use tracing::info;

use crate::client::Client;
use crate::crypto::Crypto;
use crate::protocol::v101::PROTOCOL_VERSION;
use crate::protocol::v101::device_credentials::DeviceCredential;
use crate::protocol::v101::di::done::Done;
use crate::protocol::v101::di::set_hmac::SetHmac;
use crate::storage::Storage;

use super::v101::di::app_start::AppStart;
use super::v101::di::custom::MfgInfo;
use super::v101::di::set_credentials::SetCredentials;
use super::v101::hash_hmac::{HMac, Hash};

pub(crate) struct Di<C, S, T> {
    client: Client,
    crypto: C,
    storage: S,
    state: T,
}

impl<C, S> Di<C, S, ()> {
    pub(crate) fn new(client: Client, crypto: C, storage: S) -> Self {
        Self {
            client,
            crypto,
            storage,
            state: (),
        }
    }

    pub(crate) async fn run<'a>(self, device_info: MfgInfo<'a>) -> eyre::Result<Di<C, S, Done>>
    where
        C: Crypto,
        S: Storage,
    {
        let state = Start {
            device_info: AppStart::new(device_info),
        };

        let init = Di::from((self, state));

        let set_creds = init.run().await?;

        let set_hmac = set_creds.run().await?;

        let done = set_hmac.run().await?;

        Ok(done)
    }
}

impl<'a, C, S> From<(Di<C, S, ()>, Start<'a>)> for Di<C, S, Start<'a>> {
    fn from((di, start): (Di<C, S, ()>, Start<'a>)) -> Self {
        Self {
            client: di.client,
            crypto: di.crypto,
            storage: di.storage,
            state: start,
        }
    }
}

pub(crate) struct Start<'a> {
    device_info: AppStart<MfgInfo<'a>>,
}

impl<'a, C, S> Di<C, S, Start<'a>> {
    async fn run(self) -> eyre::Result<Di<C, S, Credentials>>
    where
        C: Crypto,
    {
        let res = self.client.send(&self.state.device_info, None).await?;

        let auth = res
            .headers()
            .get(AUTHORIZATION)
            .ok_or_eyre("missing authorization header")?
            .clone();

        let set_creds = Client::parse_msg::<SetCredentials>(res).await?;

        info!("DI.AppStart successful");

        Ok(Di::from((
            self,
            Credentials {
                auth,
                creds: set_creds,
                buf: Vec::new(),
            },
        )))
    }
}

impl<'a, C, S> From<(Di<C, S, Start<'a>>, Credentials)> for Di<C, S, Credentials> {
    fn from((di, state): (Di<C, S, Start<'a>>, Credentials)) -> Self {
        Self {
            client: di.client,
            crypto: di.crypto,
            storage: di.storage,
            state,
        }
    }
}

pub(crate) struct Credentials {
    auth: HeaderValue,
    creds: SetCredentials<'static>,
    buf: Vec<u8>,
}

impl<C, S> Di<C, S, Credentials> {
    async fn run(mut self) -> eyre::Result<Di<C, S, Hmac>>
    where
        C: Crypto,
    {
        let hash = self.owner_key_hash()?;

        let hmac_secret = self.crypto.hmac_secret().await?;

        let hmac = self.ov_header_hmac(&hmac_secret).await?;

        let ov_header = self.state.creds.ov_header();

        info!(guid = %ov_header.ov_guid);

        let device_creds = DeviceCredential {
            dc_active: true,
            dc_prot_ver: PROTOCOL_VERSION,
            dc_hmac_secret: std::borrow::Cow::Owned(ByteBuf::from(hmac_secret.to_vec()?)),
            dc_device_info: ov_header.ov_device_info.clone(),
            dc_guid: ov_header.ov_guid,
            dc_rv_info: ov_header.ov_rv_info.clone(),
            dc_pub_key_hash: hash,
        };

        info!("DI.SetCredentials successful");

        Ok(Di::from((self, (SetHmac { hmac }, device_creds))))
    }

    fn owner_key_hash(&mut self) -> Result<Hash<'static>, eyre::Error>
    where
        C: Crypto,
    {
        self.state.buf.clear();

        ciborium::into_writer(
            &self.state.creds.ov_header().ov_pub_key,
            &mut self.state.buf,
        )?;

        let dc_pub_key_hash = self.crypto.hash(&self.state.buf)?;

        Ok(dc_pub_key_hash)
    }

    async fn ov_header_hmac(
        &mut self,
        hmac_secret: &CoseEncrypt0,
    ) -> Result<HMac<'static>, eyre::Error>
    where
        C: Crypto,
    {
        self.state.buf.clear();

        ciborium::into_writer(
            &self.state.creds.ov_header().ov_pub_key,
            &mut self.state.buf,
        )?;

        let hmac = self.crypto.hmac(hmac_secret, &self.state.buf).await?;

        Ok(hmac)
    }
}

impl<C, S>
    From<(
        Di<C, S, Credentials>,
        (SetHmac<'static>, DeviceCredential<'static>),
    )> for Di<C, S, Hmac>
{
    fn from(
        (di, (hmac, creds)): (
            Di<C, S, Credentials>,
            (SetHmac<'static>, DeviceCredential<'static>),
        ),
    ) -> Self {
        Self {
            client: di.client,
            crypto: di.crypto,
            storage: di.storage,
            state: Hmac {
                auth: di.state.auth,
                hmac,
                device_creds: creds,
            },
        }
    }
}

pub(crate) struct Hmac {
    auth: HeaderValue,
    hmac: SetHmac<'static>,
    device_creds: DeviceCredential<'static>,
}

impl<C, S> Di<C, S, Hmac> {
    async fn run(self) -> eyre::Result<Di<C, S, Done>>
    where
        S: Storage,
    {
        let Done {} = self
            .client
            .send_msg(&self.state.hmac, &self.state.auth)
            .await?;

        info!("DI.SetMac sucessfully");

        // TODO: store credentials
        let mut buf = Vec::new();
        ciborium::into_writer(&self.state.device_creds, &mut buf)?;

        self.storage.write("device_creds.cbor", &buf).await?;

        info!("DI.Done sucessfully");

        Ok(Di::from((self, Done)))
    }
}

impl<C, S> From<(Di<C, S, Hmac>, Done)> for Di<C, S, Done> {
    fn from((di, state): (Di<C, S, Hmac>, Done)) -> Self {
        Self {
            client: di.client,
            crypto: di.crypto,
            storage: di.storage,
            state,
        }
    }
}
