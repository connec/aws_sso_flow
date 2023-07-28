use std::{convert::Infallible, fmt, path::PathBuf};

use aws_config::SdkConfig;
use url::Url;

use crate::{
    cache::{self, Cache},
    sso::{self, GetRoleCredentialsRequest},
    sso_oidc::{self, CreateTokenError, CreateTokenRequest, RegisterClientRequest},
    SessionCredentials, SsoConfig, SsoFlowBuilder, SsoProfileError, CLIENT_NAME,
};

/// A configured AWS SSO authentication flow.
///
/// A default flow can be constructed with [`new`](Self::new).
#[allow(clippy::module_name_repetitions)]
pub struct SsoFlow<V> {
    cache: Cache,
    sso_oidc_client: sso_oidc::Client,
    sso_client: sso::Client,
    config: SsoConfig,
    verification_prompt: V,
}

impl SsoFlow<Infallible> {
    /// Construct a builder for an SSO flow.
    ///
    /// Use this to override the default flow configuration.
    #[must_use]
    pub fn builder() -> SsoFlowBuilder {
        SsoFlowBuilder::default()
    }
}

impl<V> SsoFlow<V>
where
    V: VerificationPrompt,
{
    /// Perform a default AWS SSO authentication flow with the given `verification_prompt`.
    ///
    /// The prompt should direct the user to the given URL, where they will be asked to grant
    /// access. Intermediate tokens are cached, and if the cache is still valid the user may not
    /// need to be prompted. Attempts to obtain credentials will timeout if the user hasn't followed the
    /// verification URL and granted access before the user code expires (default 10 mins).
    ///
    /// SSO configuration is sourced from AWS shared config (located with `AWS_CONFIG_FILE` and
    /// `AWS_PROFILE`) and intermediate tokens are cached in the user's OS cache directory in
    /// `aws_sso_flow/0.1/*`. The cache format is considered part of the crate's API.
    ///
    /// For more flexible configuration see [`SsoFlowBuilder`].
    ///
    /// # Example
    ///
    /// A simple prompt implementation could print the URL and ask the user to visit it:
    ///
    /// ```no_run
    /// # #[tokio::main] async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// use std::convert::Infallible;
    ///
    /// let flow = aws_sso_flow::SsoFlow::new(|url| async move {
    ///     println!("Go to {url} to sign in with SSO");
    ///     Ok::<_, Infallible>(())
    /// }).await?;
    ///
    /// let credentials = flow.authenticate().await?;
    /// # Ok(()) }
    /// ```
    ///
    /// # Errors
    ///
    /// An error is returned if a profile cannot be loaded, or if it is missing SSO configuration.
    pub async fn new(verification_prompt: V) -> Result<Self, SsoProfileError> {
        SsoFlowBuilder::default()
            .verification_prompt(verification_prompt)
            .build()
            .await
    }

    pub(crate) fn build(
        cache_dir: Option<PathBuf>,
        config: SsoConfig,
        verification_prompt: V,
    ) -> Self {
        let sdk_config = SdkConfig::builder().region(config.region.0.clone()).build();

        Self {
            cache: Cache::new(cache_dir, &config),
            sso_oidc_client: sso_oidc::Client::new(&sdk_config),
            sso_client: sso::Client::new(&sdk_config),
            config,
            verification_prompt,
        }
    }

    /// Perform the AWS SSO authentication flow and obtain credentials.
    ///
    /// # Errors
    ///
    /// An errors is returned if the authentication flow cannot complete. See [`SsoFlowError`] for
    /// details of possible errors.
    pub async fn authenticate(&self) -> Result<SessionCredentials, SsoFlowError<V::Error>> {
        let client = self
            .cache
            .get_or_init("client", || {
                self.sso_oidc_client.register_client(RegisterClientRequest {
                    client_name: CLIENT_NAME.to_string(),
                })
            })
            .await
            .map_err(|error| match error {
                cache::Error::Init(error) => SsoFlowError::Api(SsoApiError(error)),
                cache::Error::Cache(error) => SsoFlowError::Cache(SsoCacheError(error)),
            })?;

        let token = self
            .cache
            .get_or_init("token", || {
                self.sso_oidc_client.create_token(
                    CreateTokenRequest {
                        client_id: client.client_id,
                        client_secret: client.client_secret,
                        start_url: self.config.start_url.clone(),
                    },
                    self.verification_prompt.clone(),
                )
            })
            .await
            .map_err(|error| match error {
                cache::Error::Init(CreateTokenError::Api(error)) => {
                    SsoFlowError::Api(SsoApiError(error))
                }
                cache::Error::Init(CreateTokenError::VerificationPrompt(error)) => {
                    SsoFlowError::VerificationPrompt(error)
                }
                cache::Error::Init(CreateTokenError::VerificationPromptTimeout) => {
                    SsoFlowError::VerificationPromptTimeout
                }
                cache::Error::Cache(error) => SsoFlowError::Cache(SsoCacheError(error)),
            })?;

        let credentials = self
            .cache
            .get_or_init("credentials", || {
                self.sso_client
                    .get_role_credentials(GetRoleCredentialsRequest {
                        access_token: token.access_token,
                        account_id: self.config.account_id.clone(),
                        role_name: self.config.role_name.clone(),
                    })
            })
            .await
            .map_err(|error| match error {
                cache::Error::Init(error) => SsoFlowError::Api(SsoApiError(error)),
                cache::Error::Cache(error) => SsoFlowError::Cache(SsoCacheError(error)),
            })?;

        Ok(credentials.into())
    }
}

impl<V> fmt::Debug for SsoFlow<V> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("SsoFlow")
            .field("cache", &self.cache)
            .field("sso_oidc_client", &self.sso_oidc_client)
            .field("sso_client", &self.sso_client)
            .field("config", &self.config)
            .field("verification_prompt", &"_")
            .finish()
    }
}

/// An SSO verification prompt.
///
/// The AWS SSO authentication flow requires users to explicitly grant access by visiting a URL and
/// clicking a button. There are many ways this could be implemented depending on the context, so
/// verification prompts are modelled with this trait.
///
/// The trait is implemented for async functions with a single `Url` argument and returning
/// `Result<(), E>`, so a trivial prompt could look like:
///
/// ```
/// use std::convert::Infallible;
///
/// use aws_sso_flow::VerificationPrompt;
///
/// fn prompt() -> impl VerificationPrompt {
///     |verification_url| async move {
///         println!("Go to {verification_url} to grant access");
///         Ok::<_, Infallible>(())
///     }
/// }
/// ```
///
/// The `Error` associated type can be used if the prompt is fallible. Type information is preserved
/// in the event of any subsequent [`SsoFlowError`].
pub trait VerificationPrompt: Clone + Send + Sync {
    /// The future returned by the prompt.
    type Future: std::future::Future<Output = Result<(), Self::Error>> + Send;

    /// An error that could occur when attempting to prompt.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Prompt the user to grant access via the given `verification_url`.
    fn prompt(self, verification_url: Url) -> Self::Future;
}

impl<F, Fut, E> VerificationPrompt for F
where
    F: FnOnce(Url) -> Fut + Clone + Send + Sync,
    Fut: std::future::Future<Output = Result<(), E>> + Send,
    E: std::error::Error + Send + Sync + 'static,
{
    type Future = Fut;
    type Error = E;

    fn prompt(self, verification_url: Url) -> Fut {
        self(verification_url)
    }
}

/// An error that occurred during the SSO authentication flow.
#[derive(Debug)]
pub enum SsoFlowError<P: std::error::Error + Send + Sync + 'static> {
    /// Indicates that an AWS API call returned an error.
    ///
    /// This could be due to invalid configuration caught by the server, or a network issue. The
    /// error message should be sufficient to aid end-user debugging.
    Api(SsoApiError),

    /// Indicates an issue with the token cache(s).
    ///
    /// This could be due to insufficient permissions, corrupt data, or an usual OS configuration.
    /// The error message should be sufficient to aid end-user debugging.
    Cache(SsoCacheError),

    /// Indicates that an error occurred during the verification prompt.
    ///
    /// See [`VerificationPrompt`] for more information.
    VerificationPrompt(P),

    /// Indicates that the verification prompt timed out.
    VerificationPromptTimeout,
}

impl<P> fmt::Display for SsoFlowError<P>
where
    P: std::error::Error + Send + Sync + 'static,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Api(error) => write!(f, "SSO authentication failed due to: {error}"),
            Self::Cache(error) => write!(f, "SSO authentication failed due to: {error}"),
            Self::VerificationPrompt(error) => {
                write!(f, "SSO authentication failed during verification: {error}",)
            }
            Self::VerificationPromptTimeout => write!(
                f,
                "SSO authentication failed: timed out waiting for verification"
            ),
        }
    }
}

impl<P: std::error::Error + Send + Sync + 'static> std::error::Error for SsoFlowError<P> {}

/// An API error that occurred during authentication.
///
/// This could be due to invalid configuration caught by the server, or a network issue. The error
/// message should be sufficient to aid end-user debugging.
#[derive(Debug)]
pub struct SsoApiError(String);

impl fmt::Display for SsoApiError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "API error when attempting authentication: {}", self.0)
    }
}

/// An error that occurred interacting with the cache during authentication.
///
/// This could be due to insufficient permissions, corrupt data, or an usual OS configuration. The
/// error message should be sufficient to aid end-user debugging.
#[derive(Debug)]
pub struct SsoCacheError(String);

impl fmt::Display for SsoCacheError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "cache error when attempting authentication: {}", self.0)
    }
}
