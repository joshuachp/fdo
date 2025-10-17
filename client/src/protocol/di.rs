use eyre::OptionExt;
use reqwest::header::{AUTHORIZATION, HeaderValue};
use tracing::info;

use crate::client::Client;
use crate::crypto::Crypto;
use crate::protocol::v101::device_credentials::DeviceCredential;
use crate::protocol::v101::di::done::Done;
use crate::protocol::v101::di::set_hmac::SetHmac;

use super::Ctx;
use super::v101::di::app_start::AppStart;
use super::v101::di::custom::MfgInfo;
use super::v101::di::set_credentials::SetCredentials;
use super::v101::hash_hmac::{HMac, Hash};

pub(crate) enum Di<'a> {
    AppStart(DiStart<'a>),
    SetCredentials(DiSetCredentials),
    SetHmac(DiSetHmac),
}

impl<'a> Di<'a> {
    pub(crate) async fn start<C>(mut ctx: Ctx<C>, device_info: MfgInfo<'a>) -> eyre::Result<()>
    where
        C: Crypto,
    {
        let mut state = Self::AppStart(DiStart {
            device_info: AppStart::new(device_info),
        });

        state.next(&mut ctx).await?;
        state.next(&mut ctx).await?;
        state.next(&mut ctx).await?;

        Ok(())
    }

    async fn next<C>(&mut self, ctx: &mut Ctx<C>) -> eyre::Result<()>
    where
        C: Crypto,
    {
        match self {
            Di::AppStart(di_app_start) => {
                let (auth, creds) = di_app_start.run(ctx).await?;

                let state = DiSetCredentials::new(auth, creds);

                *self = Di::SetCredentials(state);
            }
            Di::SetCredentials(set_creds) => {
                let hmac = set_creds.run(ctx).await?;

                // TODO: improve the new state
                *self = Di::SetHmac(DiSetHmac::new(set_creds.auth.clone(), hmac));
            }
            Di::SetHmac(di_set_hmac) => {
                di_set_hmac.run(ctx).await?;
            }
        }

        Ok(())
    }
}

pub(crate) struct DiStart<'a> {
    device_info: AppStart<MfgInfo<'a>>,
}

impl DiStart<'_> {
    async fn run<C>(&self, ctx: &mut Ctx<C>) -> eyre::Result<(HeaderValue, SetCredentials<'static>)>
    where
        C: Crypto,
    {
        let res = ctx.client.send(&self.device_info, None).await?;

        let auth = res
            .headers()
            .get(AUTHORIZATION)
            .ok_or_eyre("missing authorization header")?
            .clone();

        let set_creds = Client::parse_msg::<SetCredentials>(res).await?;

        info!("DI.AppStart successful");

        Ok((auth, set_creds))
    }
}

pub(crate) struct DiSetCredentials {
    auth: HeaderValue,
    creds: SetCredentials<'static>,
    buf: Vec<u8>,
}

impl DiSetCredentials {
    fn new(auth: HeaderValue, creds: SetCredentials<'static>) -> Self {
        Self {
            auth,
            creds,
            buf: Vec::new(),
        }
    }

    async fn run<C>(&mut self, ctx: &mut Ctx<C>) -> eyre::Result<HMac<'static>>
    where
        C: Crypto,
    {
        let ov_header = self.creds.ov_header();

        info!(guid = %ov_header.ov_guid);

        // XXX: store this hash in device credentials
        let hash = self.owner_key_hash(ctx)?;

        let secret = ctx.crypto.secret();

        let device_creds = DeviceCredential {
            dc_active: true,
            dc_prot_ver: crate::PROTOCOL_VERSION,
            dc_hmac_secret: todo!(),
            dc_device_info: todo!(),
            dc_guid: todo!(),
            dc_rv_info: todo!(),
            dc_pub_key_hash: todo!(),
        };

        let hmac = self.ov_header_hmac(ctx)?;

        info!("DI.SetCredentials successful");

        Ok(hmac)
    }

    fn owner_key_hash<C>(&mut self, ctx: &mut Ctx<C>) -> Result<Hash<'static>, eyre::Error>
    where
        C: Crypto,
    {
        self.buf.clear();

        ciborium::into_writer(&self.creds.ov_header().ov_pub_key, &mut self.buf)?;

        let dc_pub_key_hash = ctx.crypto.hash(&self.buf)?;

        Ok(dc_pub_key_hash)
    }

    fn ov_header_hmac<C>(&mut self, ctx: &mut Ctx<C>) -> Result<HMac<'static>, eyre::Error>
    where
        C: Crypto,
    {
        self.buf.clear();

        ciborium::into_writer(&self.creds.ov_header().ov_pub_key, &mut self.buf)?;

        let hmac = ctx.crypto.hmac(&self.buf)?;

        Ok(hmac)
    }
}

pub(crate) struct DiSetHmac {
    auth: HeaderValue,
    hmac: SetHmac<'static>,
}

impl DiSetHmac {
    async fn run<C>(&self, ctx: &mut Ctx<C>) -> eyre::Result<()>
    where
        C: Crypto,
    {
        let Done {} = ctx.client.send_msg(&self.hmac, &self.auth).await?;

        info!("DI.SetMac sucessfully");

        info!("DI.Done sucessfully");

        Ok(())
    }

    fn new(auth: HeaderValue, hmac: Hash<'static>) -> Self {
        Self {
            auth,
            hmac: SetHmac { hmac },
        }
    }
}
