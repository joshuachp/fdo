use eyre::eyre;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

use self::client::Client;
use self::protocol::di::Di;
use self::protocol::v101::di::custom::MfgInfo;
use self::storage::FileStorage;

mod client;
mod crypto;
mod protocol;
mod storage;

const MANUFACTORER_URL: &str = "http://127.0.0.1:8038";

const MAC: &str = "e626207f-5fcc-456e-b1bc-250c9c8efb47";

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

    let storage = FileStorage::open("/tmp/fdo-starte".into()).await?;

    let mut crypto = crypto::software::SoftwareCrypto::create(storage.clone()).await?;

    let client = Client::new(base_url)?;

    let device_info = MfgInfo::generate(&mut crypto, MAC, "fdo-astarte").await?;

    let di = Di::new(client, crypto, storage);

    let _done = di.run(device_info).await?;

    Ok(())
}
