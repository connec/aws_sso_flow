use std::{
    env, fmt, io,
    path::{Path, PathBuf},
};

use futures::future::BoxFuture;
use tokio::{
    fs::{self, File},
    io::AsyncReadExt,
};

use crate::{SsoConfig, SsoConfigSource};

const AWS_CONFIG_FILE: &str = "AWS_CONFIG_FILE";
const AWS_CONFIG_FILE_DEFAULT: &[&str] = &[".aws", "config"];

const AWS_PROFILE: &str = "AWS_PROFILE";
const AWS_PROFILE_DEFAULT: &str = "default";

/// A reference to a profile in AWS shared configuration.
///
/// The default profile source uses the `AWS_CONFIG_FILE` and `AWS_PROFILE` environment variables,
/// but this can be overridden with [`with_config_file`](Self::with_config_file) and
/// [`with_profile`](Self::with_profile).
///
/// # Example
///
/// ```no_run
/// # #[tokio::main] async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use std::convert::Infallible;
///
/// use aws_sso_flow::{ProfileSource, SsoFlow};
///
/// let my_profile = ProfileSource::default()
///     .with_config_file(".myconfig")
///     .with_profile("my-profile");
///
/// let flow = SsoFlow::builder()
///     .config(my_profile)
///     .verification_prompt(|url| async move {
///         Ok::<_, Infallible>(())
///     })
///     .build()
///     .await?;
/// # Ok(()) }
/// ```
#[allow(clippy::module_name_repetitions)]
#[derive(Clone, Default)]
pub struct ProfileSource {
    config_file: Option<PathBuf>,
    profile: Option<String>,
}

impl ProfileSource {
    /// Set the location of the AWS shared config file.
    #[must_use]
    pub fn with_config_file(self, path: impl Into<PathBuf>) -> Self {
        Self {
            config_file: Some(path.into()),
            ..self
        }
    }

    /// Set the profile.
    #[must_use]
    pub fn with_profile(self, name: impl Into<String>) -> Self {
        Self {
            profile: Some(name.into()),
            ..self
        }
    }
}

impl SsoConfigSource for ProfileSource {
    type Future = BoxFuture<'static, Result<SsoConfig, Self::Error>>;

    type Error = SsoProfileError;

    fn load(self) -> Self::Future {
        Box::pin(async move {
            let path = self.config_file.map_or_else(get_config_file_from_env, Ok)?;
            let profile = self.profile.map_or_else(get_profile_from_env, Ok)?;

            parse_profile(&path, &profile).await
        })
    }
}

/// An error indicating missing or invalid SSO configuration.
///
/// The error message should be sufficient to aid end-user debugging.
#[derive(Debug)]
pub struct SsoProfileError(String);

impl SsoProfileError {
    fn new(error: impl Into<String>) -> Self {
        Self(error.into())
    }
}

impl fmt::Display for SsoProfileError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl std::error::Error for SsoProfileError {}

fn get_config_file_from_env() -> Result<PathBuf, SsoProfileError> {
    read_env(AWS_CONFIG_FILE)
        .and_then(|path| {
            path.map(|path| path.parse::<PathBuf>().map_err(|error| error.to_string()))
                .transpose()
        })
        .map_err(|error| {
            SsoProfileError::new(format!(
                "invalid path in environment variable {AWS_CONFIG_FILE}: {error}",
            ))
        })?
        .map_or_else(
            || {
                let mut path = dirs_next::home_dir()
                    .ok_or_else(|| SsoProfileError::new("could not determine home directory"))?;
                for segment in AWS_CONFIG_FILE_DEFAULT {
                    path.push(segment);
                }
                Ok(path)
            },
            Ok,
        )
}

fn get_profile_from_env() -> Result<String, SsoProfileError> {
    Ok(read_env(AWS_PROFILE)
        .map_err(|error| {
            SsoProfileError::new(format!(
                "invalid profile name in environment variable {AWS_PROFILE}: {error}",
            ))
        })?
        .unwrap_or_else(|| AWS_PROFILE_DEFAULT.to_string()))
}

fn read_env(name: &str) -> Result<Option<String>, String> {
    env::var(name).map(Some).or_else(|error| match error {
        env::VarError::NotPresent => Ok(None),
        env::VarError::NotUnicode(data) => Err(format!("{data:?} contains invalid UTF-8")),
    })
}

fn parse_profile_name(line: &str) -> Option<&str> {
    line.trim().strip_suffix(']').and_then(|line| {
        line.strip_prefix("[profile ")
            .or_else(|| line.strip_prefix('['))
    })
}

async fn parse_profile(path: &Path, profile: &str) -> Result<SsoConfig, SsoProfileError> {
    let config = read_file(path).await.map_err(|error| {
        SsoProfileError::new(format!(
            "unable to read config file {}: {error}",
            path.display()
        ))
    })?;

    let mut in_profile = false;
    let mut region = None;
    let mut start_url = None;
    let mut account_id = None;
    let mut role_name = None;

    for line in config.lines() {
        let line = line.trim_matches(' ');
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if let Some(next_profile) = parse_profile_name(line) {
            if in_profile {
                break;
            }
            in_profile = next_profile == profile;
        } else if in_profile {
            let mut kv = line
                .splitn(2, '=')
                .map(|kv| kv.trim_matches(' '))
                .filter(|kv| !kv.is_empty());
            match [kv.next(), kv.next()] {
                [Some("sso_region"), Some(value)] => region = Some(value.to_string()),
                [Some("sso_start_url"), Some(value)] => start_url = Some(value.to_string()),
                [Some("sso_account_id"), Some(value)] => {
                    account_id = Some(value.to_string());
                }
                [Some("sso_role_name"), Some(value)] => role_name = Some(value.to_string()),
                _ => {}
            }
        }
    }

    if !in_profile {
        return Err(SsoProfileError::new(format!(
            "profile {} is not defined in in config file {}",
            profile,
            path.display(),
        )));
    }

    match (region, start_url, account_id, role_name) {
        (Some(region), Some(start_url), Some(account_id), Some(role_name)) => {
            let region = region.parse().map_err(|error| {
                SsoProfileError::new(format!(
                    "error in profile {} in config file {}: {}",
                    profile,
                    path.display(),
                    error
                ))
            })?;
            Ok(SsoConfig {
                region,
                start_url,
                account_id,
                role_name,
            })
        }
        (region, start_url, account_id, role_name) => {
            let missing: Vec<_> = region
                .map_or_else(|| Some("sso_region"), |_| None)
                .into_iter()
                .chain(start_url.map_or_else(|| Some("sso_start_url"), |_| None))
                .chain(account_id.map_or_else(|| Some("sso_account_id"), |_| None))
                .chain(role_name.map_or_else(|| Some("sso_role_name"), |_| None))
                .collect();
            Err(SsoProfileError::new(format!(
                "incomplete SSO configuration in profile {}; missing: {}",
                profile,
                missing.join(", ")
            )))
        }
    }
}

async fn read_file(path: &Path) -> Result<String, io::Error> {
    let meta = fs::metadata(&path).await?;
    if !meta.is_file() {
        return Err(io::Error::new(io::ErrorKind::Other, "not a file"));
    }

    let mut file = File::open(&path)
        .await
        .expect("couldn't open file after stat");
    let mut file_content = String::new();
    file.read_to_string(&mut file_content).await?;

    Ok(file_content)
}
