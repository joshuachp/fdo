use coset::{CoseEncrypt0, TaggedCborSerializable};
use reqwest::header::HeaderValue;
use serde_bytes::ByteBuf;
use tracing::{debug, info};

use crate::Ctx;
use crate::client::{Client, NeedsAuth};
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

pub(crate) const DEVICE_CREDS: &str = "device_creds.cbor";

pub(crate) struct Di<T, A = HeaderValue> {
    client: Client<A>,
    state: T,
}

impl<'a> Di<Start<'a>, NeedsAuth> {
    pub(crate) fn new(client: Client<NeedsAuth>, device_info: MfgInfo<'a>) -> Self {
        Self {
            client,
            state: Start {
                device_info: AppStart::new(device_info),
            },
        }
    }

    pub(crate) async fn create_credentials<C, S>(
        self,
        ctx: &mut Ctx<'_, C, S>,
    ) -> eyre::Result<DeviceCredential<'static>>
    where
        C: Crypto,
        S: Storage,
    {
        debug!(device_info = ?self.state.device_info);

        if let Some(done) = Self::read_existing(ctx).await? {
            return Ok(done);
        }

        debug!("credentials not found, running device initialization");

        let set_creds = self.run().await?;

        let set_hmac = set_creds.run(ctx).await?;

        let dc = set_hmac.run(ctx).await?;

        Ok(dc)
    }

    pub(crate) async fn read_existing<C, S>(
        ctx: &mut Ctx<'_, C, S>,
    ) -> Result<Option<DeviceCredential<'static>>, eyre::Error>
    where
        S: Storage,
    {
        let Some(creds) = ctx.storage.read(DEVICE_CREDS).await? else {
            return Ok(None);
        };

        let device_credentials: DeviceCredential =
            ciborium::from_reader(std::io::Cursor::new(creds))?;

        info!("retrieved existing device credentials");

        Ok(Some(device_credentials))
    }
}

pub(crate) struct Start<'a> {
    device_info: AppStart<'a, MfgInfo<'a>>,
}

impl<'a> Di<Start<'a>, NeedsAuth> {
    async fn run(self) -> eyre::Result<Di<Credentials>> {
        let (set_creds, auth) = self.client.init(&self.state.device_info).await?;

        info!("DI.AppStart successful");

        Ok(Di {
            client: self.client.set_auth(auth),
            state: Credentials::new(set_creds),
        })
    }
}

pub(crate) struct Credentials {
    creds: SetCredentials<'static>,
}
impl Credentials {
    fn new(set_creds: SetCredentials<'static>) -> Self {
        Self { creds: set_creds }
    }
}

impl Di<Credentials> {
    async fn run<C, S>(mut self, ctx: &mut Ctx<'_, C, S>) -> eyre::Result<Di<Hmac>>
    where
        C: Crypto,
    {
        let hash = self.owner_key_hash(ctx)?;

        let hmac_secret = ctx.crypto.hmac_secret().await?;

        let hmac = self.ov_header_hmac(ctx, &hmac_secret).await?;

        let ov_header = self.state.creds.ov_header;

        info!(guid = %ov_header.ov_guid);

        let device_creds = DeviceCredential {
            dc_active: true,
            dc_prot_ver: PROTOCOL_VERSION,
            dc_hmac_secret: std::borrow::Cow::Owned(ByteBuf::from(hmac_secret.to_tagged_vec()?)),
            dc_device_info: ov_header.ov_device_info.clone(),
            dc_guid: ov_header.ov_guid,
            dc_rv_info: ov_header.ov_rv_info.clone(),
            dc_pub_key_hash: hash,
        };

        info!("DI.SetCredentials successful");

        Ok(Di {
            client: self.client,
            state: Hmac {
                hmac: SetHmac { hmac },
                device_creds,
            },
        })
    }

    fn owner_key_hash<C, S>(
        &mut self,
        ctx: &mut Ctx<'_, C, S>,
    ) -> Result<Hash<'static>, eyre::Error>
    where
        C: Crypto,
    {
        let mut buf = Vec::new();

        ciborium::into_writer(&self.state.creds.ov_header.ov_pub_key, &mut buf)?;

        let dc_pub_key_hash = ctx.crypto.hash(&buf);

        debug_assert!(dc_pub_key_hash.hashtype.is_hash());

        Ok(dc_pub_key_hash)
    }

    async fn ov_header_hmac<C, S>(
        &mut self,
        ctx: &mut Ctx<'_, C, S>,
        hmac_secret: &CoseEncrypt0,
    ) -> Result<HMac<'static>, eyre::Error>
    where
        C: Crypto,
    {
        let data = self.state.creds.ov_header.bytes()?;

        let hmac = ctx.crypto.hmac(hmac_secret, data).await?;

        debug_assert!(hmac.hashtype.is_hmac());

        Ok(hmac)
    }
}

pub(crate) struct Hmac {
    hmac: SetHmac<'static>,
    device_creds: DeviceCredential<'static>,
}

impl Di<Hmac> {
    async fn run<C, S>(self, ctx: &mut Ctx<'_, C, S>) -> eyre::Result<DeviceCredential<'static>>
    where
        S: Storage,
    {
        let Done {} = self.client.send_msg(&self.state.hmac).await?;

        info!("DI.SetMac sucessfully");

        // TODO: separate store credentials
        let mut buf = Vec::new();
        ciborium::into_writer(&self.state.device_creds, &mut buf)?;

        ctx.storage.write(DEVICE_CREDS, &buf).await?;

        info!("DI.Done sucessfully");

        Ok(self.state.device_creds)
    }
}
