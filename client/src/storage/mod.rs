use std::io::ErrorKind;
use std::path::PathBuf;

use tokio::fs::{DirBuilder, File};
use tokio::io::AsyncWriteExt;
use zeroize::Zeroizing;

pub(crate) trait Storage {
    type R: tokio::io::AsyncRead;

    async fn write_immutable(&self, file: &str, content: &[u8]) -> eyre::Result<()>;

    async fn write(&self, file: &str, content: &[u8]) -> eyre::Result<()>;

    async fn read(&self, file: &str) -> eyre::Result<Option<Vec<u8>>>;

    async fn read_secret(&self, file: &str) -> eyre::Result<Option<Zeroizing<Vec<u8>>>> {
        self.read(file).await.map(|value| value.map(Zeroizing::new))
    }

    async fn exists(&self, file: &str) -> eyre::Result<bool>;
}

#[derive(Debug, Clone)]
pub(crate) struct FileStorage {
    dir: PathBuf,
}

impl FileStorage {
    pub(crate) async fn open(dir: PathBuf) -> eyre::Result<Self> {
        let mut builder = DirBuilder::new();
        builder.recursive(true).mode(0o700);

        builder.create(&dir).await?;

        Ok(Self { dir })
    }
}

impl Storage for FileStorage {
    type R = tokio::io::BufReader<File>;

    async fn write_immutable(&self, file: &str, content: &[u8]) -> eyre::Result<()> {
        let mut file = File::options()
            .create_new(true)
            .write(true)
            .mode(0o700)
            .open(self.dir.join(file))
            .await?;

        file.write_all(content).await?;

        // TODO make immutable

        Ok(())
    }

    async fn write(&self, file: &str, content: &[u8]) -> eyre::Result<()> {
        let mut file = File::options()
            .create_new(true)
            .write(true)
            .mode(0o700)
            .open(self.dir.join(file))
            .await?;

        file.write_all(content).await?;

        Ok(())
    }

    async fn read(&self, file: &str) -> eyre::Result<Option<Vec<u8>>> {
        match tokio::fs::read(self.dir.join(file)).await {
            Ok(file) => Ok(Some(file)),
            Err(err) if err.kind() == ErrorKind::NotFound => Ok(None),
            Err(err) => Err(err.into()),
        }
    }

    async fn exists(&self, file: &str) -> eyre::Result<bool> {
        tokio::fs::try_exists(self.dir.join(file))
            .await
            .map_err(eyre::Report::new)
    }
}
