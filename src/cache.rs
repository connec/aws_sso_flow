use std::{
    cell::Cell,
    hash::{Hash, Hasher},
    io,
    path::{Path, PathBuf},
};

use chrono::{DateTime, Utc};
use futures::TryFutureExt;
use md5::{Digest, Md5};
use tokio::fs;

const CACHE_BUFFER: std::time::Duration = std::time::Duration::from_secs(60);

pub(crate) struct Cache {
    dir: Option<PathBuf>,
    suffix: String,
}

impl Cache {
    pub(crate) fn new<S: Hash>(dir: Option<PathBuf>, suffix: S) -> Self {
        let mut hasher = Md5Hasher::new();
        suffix.hash(&mut hasher);

        Self {
            dir,
            suffix: format!("{:x}", hasher.finish()),
        }
    }

    pub(crate) async fn get_or_init<F, Fut, T, E>(
        &self,
        prefix: &str,
        init: F,
    ) -> Result<T, Error<E>>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<T, E>>,
        T: Expiry + serde::de::DeserializeOwned + serde::Serialize,
    {
        let path = self
            .dir
            .as_deref()
            .map(|dir| dir.join(format!("{}-{}.json", prefix, self.suffix)));

        if let Some(path) = &path {
            match fs::read_to_string(&path).await {
                Ok(content) => {
                    let value: T = serde_json::from_str(&content)
                        .map_err(|error| Error::cache("corrupt", path, error))?;
                    if value.expires_at()
                        + chrono::Duration::from_std(CACHE_BUFFER).expect("expiry overflow")
                        > Utc::now()
                    {
                        return Ok(value);
                    }
                }
                Err(error) if error.kind() != io::ErrorKind::NotFound => {
                    return Err(Error::cache("failed to read", path, error));
                }
                Err(_) => {
                    // continue
                }
            }
        }

        let value = init().await.map_err(Error::Init)?;

        if let Some(path) = &path {
            let content =
                serde_json::to_string_pretty(&value).expect("tried to cache unserializable value");
            fs::create_dir_all(path.parent().expect("path in dir"))
                .and_then(|_| fs::write(path, &content))
                .await
                .map_err(|error| Error::cache("failed to write", path, error))?;
        }

        Ok(value)
    }
}

pub(crate) enum Error<E> {
    Cache(String),
    Init(E),
}

impl<E> Error<E> {
    fn cache(
        msg: &'static str,
        path: &Path,
        error: impl Into<Box<dyn std::error::Error + Send + Sync + 'static>>,
    ) -> Self {
        Self::Cache(format!(
            "{} cache file {} due to: {}",
            msg,
            path.display(),
            error.into()
        ))
    }
}

pub(crate) trait Expiry {
    fn expires_at(&self) -> DateTime<Utc>;
}

struct Md5Hasher {
    inner: Cell<Option<Md5>>,
}

impl Md5Hasher {
    fn new() -> Self {
        Self {
            inner: Cell::new(Some(Md5::new())),
        }
    }
}

impl Hasher for Md5Hasher {
    fn write(&mut self, bytes: &[u8]) {
        self.inner
            .get_mut()
            .as_mut()
            .expect("wrote to finished hasher")
            .update(bytes);
    }

    fn finish(&self) -> u64 {
        let digest: [u8; 16] = self
            .inner
            .take()
            .expect("finished hash twice")
            .finalize()
            .into();
        u64::from_be_bytes([
            digest[0], digest[1], digest[2], digest[3], digest[4], digest[5], digest[6], digest[7],
        ]) ^ u64::from_be_bytes([
            digest[8], digest[9], digest[10], digest[11], digest[12], digest[13], digest[14],
            digest[15],
        ])
    }
}
