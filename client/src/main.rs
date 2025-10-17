use eyre::eyre;
use reqwest::header::{HeaderName, HeaderValue};
use serde::Serialize;
use serde::de::DeserializeOwned;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

use self::protocol::Ctx;
use self::protocol::di::Di;
use self::protocol::v101::di::custom::MfgInfo;
use self::protocol::v101::{Msgtype, Protver};

mod client;
mod crypto;
mod protocol;
mod storage;

const MANUFACTORER_URL: &str = "http://127.0.0.1:8038";

const MAC: &str = "e626207f-5fcc-456e-b1bc-250c9c8efb47";

const MIME: HeaderValue = HeaderValue::from_static("application/cbor");
const MESSAGE_TYPE: HeaderName = HeaderName::from_static("message-type");

const PROTOCOL_VERSION_MAJOR: Protver = 1;
const PROTOCOL_VERSION_MINOR: Protver = 1;
const PROTOCOL_VERSION: Protver = PROTOCOL_VERSION_MAJOR * 100 + PROTOCOL_VERSION_MINOR;

trait Message: Serialize + DeserializeOwned {
    const MSG_TYPE: Msgtype;
}

trait ClientMessage: Message {
    type Response<'a>: Message;
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(
            tracing_subscriber::EnvFilter::builder()
                .with_default_directive("info".parse()?)
                .from_env_lossy(),
        )
        .try_init()?;

    color_eyre::install()?;

    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .map_err(|_| eyre!("couldn't install crypto provider"))?;

    let base_url = url::Url::parse(MANUFACTORER_URL)?;

    let mut crypto = crypto::software::SoftwareCrypto::create()?;

    let device_info = MfgInfo::generate(&mut crypto, MAC, "fdo-astarte")?;

    let ctx = Ctx::create(base_url, crypto)?;

    Di::start(ctx, device_info).await?;

    Ok(())
}
