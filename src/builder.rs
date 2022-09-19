use std::{convert::Infallible, path::PathBuf};

use crate::{ProfileSource, Region, SsoFlow, VerificationPrompt, CLIENT_NAME};

/// Builder for [`SsoFlow`].
///
/// This allows aspects of the authentication flow to be configured.
///
/// # Example
///
/// ```
/// # #[tokio::main] async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use std::{convert::Infallible, fmt};
///
/// use aws_sso_flow::{SsoConfig, SsoFlowBuilder};
///
/// let flow = SsoFlowBuilder::new()
///     // change the cache directory to "$PWD/.cache" instead of OS cache dir
///     .cache_dir(".cache")
///     // use hard-coded SSO configuration instead of loading from profile
///     .config(SsoConfig {
///         region: "eu-west-1".parse().unwrap(),
///         start_url: "myorg.awsapps.com/start".to_string(),
///         account_id: "012345678910".to_string(),
///         role_name: "PowerUser".to_string(),
///     })
///     // always error if prompted (auth still possible if tokens are cached)
///     .verification_prompt(|url| async move {
///         Err(NonInteractive)
///     })
///     .build()
///     .await
///     .expect("infallible");
///
/// #[derive(Debug)]
/// struct NonInteractive;
///
/// impl fmt::Display for NonInteractive {
///     fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
///         write!(f, "interactive authentication required")
///     }
/// }
///
/// impl std::error::Error for NonInteractive {}
/// # Ok(())
/// # }
/// ```
#[allow(clippy::module_name_repetitions)]
pub struct SsoFlowBuilder<S = ProfileSource, V = Infallible> {
    cache_dir: Option<PathBuf>,
    config_source: S,
    verification_prompt: Option<V>,
}

impl SsoFlowBuilder<ProfileSource, Infallible> {
    /// Construct an [`SsoFlow`] builder with default configuration.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl Default for SsoFlowBuilder<ProfileSource, Infallible> {
    fn default() -> Self {
        Self {
            cache_dir: None,
            config_source: ProfileSource::default(),
            verification_prompt: None,
        }
    }
}

impl<S, V> SsoFlowBuilder<S, V> {
    /// Set the cache directory.
    ///
    /// The AWS SSO authentication flow involves obtaining tokens from AWS SSO OIDC and session
    /// credentials from AWS SSO. Tokens and credentials will be cached in a directory called
    /// `aws_sso_flow@0.1`. The cache format is considered part of the crate's API.
    ///
    /// By default, caches are created under the user's cache directory (see
    /// [`dirs_next::cache_dir`]).
    #[must_use]
    pub fn cache_dir(self, path: impl Into<PathBuf>) -> Self {
        Self {
            cache_dir: Some(path.into()),
            ..self
        }
    }

    /// Set the SSO configuration source.
    ///
    /// By default, SSO configuration is sourced from AWS shared config (located with
    /// `AWS_CONFIG_FILE` and `AWS_PROFILE`).
    #[must_use]
    pub fn config<NewS>(self, config_source: NewS) -> SsoFlowBuilder<NewS, V>
    where
        S: SsoConfigSource,
    {
        SsoFlowBuilder {
            cache_dir: self.cache_dir,
            config_source,
            verification_prompt: self.verification_prompt,
        }
    }

    /// Set the verification prompt handler.
    ///
    /// Users need to visit a URL and explicitly grant access in order to authenticate via SSO. Note
    /// that token caching means that prompting should occur infrequently, depending on the AWS SSO
    /// configuration.
    #[must_use]
    pub fn verification_prompt<NewV>(self, verification_prompt: NewV) -> SsoFlowBuilder<S, NewV>
    where
        NewV: VerificationPrompt,
    {
        SsoFlowBuilder {
            cache_dir: self.cache_dir,
            config_source: self.config_source,
            verification_prompt: Some(verification_prompt),
        }
    }
}

impl<S, V> SsoFlowBuilder<S, V>
where
    S: SsoConfigSource,
    V: VerificationPrompt,
{
    /// Build an [`SsoFlow`] with the given configuration.
    ///
    /// # Errors
    ///
    /// Returns any errors encountered when loading the [`SsoConfigSource`].
    pub async fn build(self) -> Result<SsoFlow<V>, S::Error> {
        let config = self.config_source.load().await?;

        // We can unwrap here because the only way to construct a new `SsoFlowBuilder` is via
        // `new`, which sets `V = Infallible` which doesn't impl `VerificationPrompt`. For
        // `V: VerificationPrompt` to hold it must have been set explicitly, in which case it will
        // be `Some`.
        let verification_prompt = self
            .verification_prompt
            .expect("verification_prompt must be set");

        Ok(SsoFlow::build(
            self.cache_dir.or_else(Self::default_cache_dir),
            config,
            verification_prompt,
        ))
    }

    fn default_cache_dir() -> Option<PathBuf> {
        dirs_next::cache_dir().map(|mut path| {
            path.push(CLIENT_NAME);
            path
        })
    }
}

/// A source of SSO configuration.
///
/// This trait is more intended to facilitate precise error handling in [`SsoFlowBuilder::build`],
/// but it could also be used to implement alternative configuration sources.
pub trait SsoConfigSource {
    /// The future returned by the config source.
    type Future: std::future::Future<Output = Result<SsoConfig, Self::Error>>;

    /// The error that might occur when sourcing the configuration.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Load the SSO configuration.
    fn load(self) -> Self::Future;
}

/// AWS SSO configuration.
#[derive(Hash)]
pub struct SsoConfig {
    /// The AWS region in which SSO was setup.
    ///
    /// All AWS API calls are performed in this region.
    pub region: Region,

    /// The URL for the AWS SSO user portal.
    pub start_url: String,

    /// The AWS account to sign in to.
    pub account_id: String,

    /// The name of the AWS IAM Role to assume in the account.
    ///
    /// This should be the role name as it appears in SSO configuration.
    pub role_name: String,
}

impl SsoConfigSource for SsoConfig {
    type Future = futures::future::Ready<Result<Self, Self::Error>>;

    type Error = Infallible;

    fn load(self) -> Self::Future {
        futures::future::ready(Ok(self))
    }
}
